#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "shared_freelist.h"

/*
 * Size-bucketed lock-free freelist over a caller-owned linear slab.
 * The primitives here are used by utils/shared_mem.c's shared string
 * heap; they are factored into their own TU so a bounds-check test
 * can drive them against a fake heap without linking the whole shm
 * subsystem.
 *
 * Head-word packing (arch-portable — no assumption about pointer
 * width or canonical VA layout, so identical on x86-64/arm64/riscv/
 * s390x/x86-64-5-level):
 *
 *   low 32 bits  = token = (slot_offset_in_heap + 1)
 *   high 32 bits = version counter (ABA guard)
 *
 * Token 0 is the empty-list sentinel; offset+1 guarantees offset 0
 * never encodes to 0.  A slot's own first uint32_t stores the NEXT
 * slot's token in the same encoding (no version bits — those live
 * only in the head word).
 *
 * The 32-bit version is effectively unwrappable in practice: a
 * targeted ABA would need 2^32 push/pop pairs interleaved between a
 * victim's load and CAS; at sub-microsecond critical sections and a
 * process-bounded fuzzer this is astronomically improbable.
 *
 * Threat model: the slab lives in MAP_SHARED memory that trinity's
 * threat model treats as fuzzer-writable.  Any token read from a
 * shared word — the head or a slot's link — may therefore be a
 * stomped value.  Every such token is validated against the caller's
 * (heap_base, heap_capacity, slot_size) before ANY dereference; a
 * failing check drops the operation safely (pop returns NULL, push
 * refuses to link) rather than wild-reading/writing off the slab.
 * See the block comment above shared_freelist_pop() for the exact
 * check.  This mirrors the "read the source of truth, drop on
 * uncertainty" armour applied to the occupied_mask path elsewhere.
 */

#define FREELIST_OFF_MASK	((uint64_t)0xffffffffULL)
#define FREELIST_VER_SHIFT	32

const size_t shared_freelist_bucket_sizes[8] = {
	8, 16, 32, 64, 128, 256, 512, 1024
};

int shared_freelist_bucket(size_t aligned_size)
{
	unsigned int i;

	for (i = 0; i < 8; i++) {
		if (aligned_size <= shared_freelist_bucket_sizes[i])
			return (int)i;
	}
	return -1;
}

/*
 * A token from a shared word is trustworthy for dereference iff it is
 * a non-empty sentinel AND names a fully-in-slab slot of slot_size
 * bytes: token != 0, token <= heap_capacity, and
 * token - 1 + slot_size <= heap_capacity.  Any failing case is a
 * stomped head or link and must be dropped without touching memory.
 */
static bool token_in_bounds(uint32_t token, size_t heap_capacity,
			    size_t slot_size)
{
	size_t offset;

	if (token == 0)
		return false;
	if ((size_t)token > heap_capacity)
		return false;
	offset = (size_t)token - 1;
	if (offset + slot_size > heap_capacity)
		return false;
	return true;
}

void *shared_freelist_pop(uint64_t *head, char *heap_base,
			  size_t heap_capacity, size_t slot_size)
{
	uint64_t old_tagged, new_tagged;
	uint32_t token, next_token;
	uint32_t new_ver;
	void *p;

	old_tagged = __atomic_load_n(head, __ATOMIC_ACQUIRE);
	do {
		token = (uint32_t)(old_tagged & FREELIST_OFF_MASK);
		if (token == 0)
			return NULL;
		/*
		 * Head token came out of a shared word; validate before
		 * we translate it to a pointer and deref.  A wild token
		 * would aim p up to ~4 GiB past heap_base on 64-bit
		 * userland — past the guard pages into unrelated shm
		 * (kcov bitmap, ring pages, …).  Drop the bucket for
		 * this call rather than take the wild read/memset.
		 */
		if (!token_in_bounds(token, heap_capacity, slot_size))
			return NULL;
		p = heap_base + (token - 1);
		/* Slot's first uint32_t holds the next slot's token
		 * (offset+1), with no version bits — versions live only
		 * in the head. */
		next_token = *(uint32_t *)p;
		/*
		 * next_token is also from a shared word (the previous
		 * pusher wrote it into the slot before its release-CAS,
		 * but the slot is fuzzer-reachable between then and now).
		 * If it's out of range, refuse to install it as the new
		 * head — a wild new head would just fail the next pop's
		 * bounds check and permanently poison this bucket.  Fall
		 * through with next_token = 0 so the new head detaches
		 * the wild chain cleanly and future pops find an empty
		 * list here.
		 */
		if (next_token != 0 &&
		    !token_in_bounds(next_token, heap_capacity, slot_size))
			next_token = 0;
		new_ver = (uint32_t)(old_tagged >> FREELIST_VER_SHIFT) + 1;
		new_tagged = ((uint64_t)next_token & FREELIST_OFF_MASK) |
			     ((uint64_t)new_ver << FREELIST_VER_SHIFT);
	} while (!__atomic_compare_exchange_n(head, &old_tagged, new_tagged,
					      false,
					      __ATOMIC_ACQ_REL,
					      __ATOMIC_ACQUIRE));

	memset(p, 0, slot_size);
	return p;
}

void shared_freelist_push(uint64_t *head, void *p, char *heap_base,
			  size_t heap_capacity, size_t slot_size)
{
	uint64_t old_tagged, new_tagged;
	uint32_t my_token, new_ver;
	ptrdiff_t off;

	/*
	 * Refuse to link a pointer that isn't fully inside the slab.
	 * A stomped obj->…->name handed to free_shared_str() would
	 * otherwise become a wild token here for the next popper to
	 * dereference; leaking the slot is the safe outcome.
	 */
	if (p == NULL)
		return;
	off = (char *)p - heap_base;
	if (off < 0)
		return;
	if ((size_t)off + slot_size > heap_capacity)
		return;

	memset(p, 0, slot_size);
	my_token = (uint32_t)off + 1;
	old_tagged = __atomic_load_n(head, __ATOMIC_RELAXED);
	do {
		/* Store only the token half of the previous head into
		 * our slot — the version stays in the head word. */
		*(uint32_t *)p = (uint32_t)(old_tagged & FREELIST_OFF_MASK);
		new_ver = (uint32_t)(old_tagged >> FREELIST_VER_SHIFT) + 1;
		new_tagged = ((uint64_t)my_token & FREELIST_OFF_MASK) |
			     ((uint64_t)new_ver << FREELIST_VER_SHIFT);
	} while (!__atomic_compare_exchange_n(head, &old_tagged, new_tagged,
					      false,
					      __ATOMIC_RELEASE,
					      __ATOMIC_RELAXED));
}
