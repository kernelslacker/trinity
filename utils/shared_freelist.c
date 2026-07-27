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
 * Head-word packing (arch-portable -- no assumption about pointer
 * width or canonical VA layout, so identical on x86-64/arm64/riscv/
 * s390x/x86-64-5-level):
 *
 *   low 32 bits  = token = (slot_offset_in_heap + 1)
 *   high 32 bits = version counter (ABA guard)
 *
 * Token 0 is the empty-list sentinel; offset+1 guarantees offset 0
 * never encodes to 0.  A slot's own first uint32_t stores the NEXT
 * slot's token in the same encoding (no version bits -- those live
 * only in the head word).
 *
 * The 32-bit version is effectively unwrappable in practice: a
 * targeted ABA would need 2^32 push/pop pairs interleaved between a
 * victim's load and CAS; at sub-microsecond critical sections and a
 * process-bounded fuzzer this is astronomically improbable.
 *
 * Threat model: the slab lives in MAP_SHARED memory that trinity's
 * threat model treats as fuzzer-writable.  Any token read from a
 * shared word -- the head or a slot's link -- may therefore be a
 * stomped value.  Bounds checks (see token_in_bounds() below) reject
 * tokens that name off-slab addresses.  But an in-bounds forgery can
 * still name a *live* slot, a slot from *another bucket*, or an
 * *aligned interior* address within a live slot: bounds prove
 * extent-in-slab, not slot provenance.
 *
 * Provenance armour: the caller passes in a per-slot state array that
 * lives OUTSIDE the fuzzer-writable slab (see shared_freelist.h for
 * the encoding).  Every pop atomically CASes state from
 * FREE(bucket_idx) -> LIVE(bucket_idx), and every push mirrors the
 * transition on the other side.  A forged token that survives bounds
 * still fails the state CAS -- link-to-live, cross-bucket, and
 * interior-offset all collapse to "state is not FREE(bucket_idx)" --
 * and the slot is leaked without touching slab memory.  Overlapping
 * allocations require *linking* the same address into two chains;
 * refusing the link is sufficient.
 */

#define FREELIST_OFF_MASK	((uint64_t)0xffffffffULL)
#define FREELIST_VER_SHIFT	32

const size_t shared_freelist_bucket_sizes[SHARED_FREELIST_NUM_BUCKETS] = {
	8, 16, 32, 64, 128, 256, 512, 1024
};

int shared_freelist_bucket(size_t aligned_size)
{
	unsigned int i;

	for (i = 0; i < SHARED_FREELIST_NUM_BUCKETS; i++) {
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

/*
 * Attempt the FREE(bucket_idx) -> LIVE(bucket_idx) transition on the
 * per-slot state byte.  Success proves the caller has exclusive
 * ownership of the slot (the state array lives outside the fuzz-
 * exposed slab, so only our own alloc/free code writes it).  Failure
 * means the slot is not a free slot for this bucket -- forged token
 * to a live slot, a wrong-bucket slot, or an interior/uncarved offset
 * -- and the caller must leak.
 */
static bool claim_slot(uint8_t *state, size_t offset,
		       unsigned int bucket_idx)
{
	uint8_t expected = SHARED_FREELIST_STATE_FREE(bucket_idx);

	return __atomic_compare_exchange_n(
		&state[offset / SHARED_FREELIST_SLOT_STRIDE],
		&expected,
		SHARED_FREELIST_STATE_LIVE(bucket_idx),
		false,
		__ATOMIC_ACQ_REL,
		__ATOMIC_ACQUIRE);
}

/*
 * Mirror transition for push: LIVE(bucket_idx) -> FREE(bucket_idx).
 * A concurrent double-free (two calls to push the same slot) sees
 * one CAS win and the other fail -- the loser leaks its stale
 * pointer rather than linking the slot onto two chains.  Also the
 * fail path for cross-bucket push (state is LIVE for a different
 * bucket) and interior/uncarved push (state is 0).
 */
static bool release_slot(uint8_t *state, size_t offset,
			 unsigned int bucket_idx)
{
	uint8_t expected = SHARED_FREELIST_STATE_LIVE(bucket_idx);

	return __atomic_compare_exchange_n(
		&state[offset / SHARED_FREELIST_SLOT_STRIDE],
		&expected,
		SHARED_FREELIST_STATE_FREE(bucket_idx),
		false,
		__ATOMIC_ACQ_REL,
		__ATOMIC_ACQUIRE);
}

void *shared_freelist_pop(uint64_t *head, uint8_t *state,
			  unsigned int bucket_idx,
			  char *heap_base, size_t heap_capacity,
			  size_t slot_size)
{
	uint64_t old_tagged, new_tagged;
	uint32_t token, next_token;
	uint32_t new_ver;
	size_t offset;
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
		 * userland -- past the guard pages into unrelated shm
		 * (kcov bitmap, ring pages, ...).  Drop the bucket for
		 * this call rather than take the wild read/memset.
		 */
		if (!token_in_bounds(token, heap_capacity, slot_size))
			return NULL;
		offset = (size_t)token - 1;
		/*
		 * Reject aligned-but-non-slot-start offsets up front.
		 * Every legitimate slot begins at a multiple of
		 * SHARED_FREELIST_SLOT_STRIDE, so a token that violates
		 * this is a forgery aimed at an interior address (or a
		 * misalignment that would confuse the state lookup).
		 * The state array covers slot-start indices only; a
		 * later state CAS on an interior byte would spuriously
		 * see UNCARVED (0) and correctly fail, but the up-front
		 * reject keeps the failure mode obvious and lets us
		 * avoid deref'ing p at all.
		 */
		if ((offset & (SHARED_FREELIST_SLOT_STRIDE - 1U)) != 0)
			return NULL;
		p = heap_base + offset;
		/* Slot's first uint32_t holds the next slot's token
		 * (offset+1), with no version bits -- versions live only
		 * in the head. */
		next_token = *(uint32_t *)p;
		/*
		 * next_token is also from a shared word (the previous
		 * pusher wrote it into the slot before its release-CAS,
		 * but the slot is fuzzer-reachable between then and now).
		 * If it's out of range, refuse to install it as the new
		 * head -- a wild new head would just fail the next pop's
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

	/*
	 * Head advanced.  Claim the slot via the per-slot state CAS.
	 * A failing CAS proves the token was a forgery (live slot,
	 * wrong-bucket slot, or interior/uncarved offset): leak the
	 * slot without memset'ing it.  The state array remains its
	 * current truth so a subsequent legitimate push of the same
	 * address for the correct bucket still succeeds.
	 */
	if (!claim_slot(state, offset, bucket_idx))
		return NULL;

	memset(p, 0, slot_size);
	return p;
}

void shared_freelist_push(uint64_t *head, uint8_t *state,
			  unsigned int bucket_idx,
			  void *p, char *heap_base,
			  size_t heap_capacity, size_t slot_size)
{
	uint64_t old_tagged, new_tagged;
	uint32_t my_token, new_ver;
	ptrdiff_t off;
	size_t off_u;

	/*
	 * Refuse to link a pointer that isn't fully inside the slab.
	 * A stomped obj->...->name handed to free_shared_str() would
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
	off_u = (size_t)off;
	/*
	 * Same slot-start rule as pop: an aligned-but-interior offset
	 * cannot legitimately land here.  Reject up front so a forged
	 * free() of an interior address cannot install itself onto a
	 * chain (from which the next popper would hand out an
	 * overlapping allocation).
	 */
	if ((off_u & (SHARED_FREELIST_SLOT_STRIDE - 1U)) != 0)
		return;

	/*
	 * Atomically transition LIVE(bucket_idx) -> FREE(bucket_idx)
	 * BEFORE touching the slab or the head.  A failing CAS means
	 * one of: (a) double-free of a slot already on some free list,
	 * (b) push to a bucket that doesn't own the slot, (c) push of
	 * an interior/uncarved offset that happens to lie inside the
	 * slab.  In every case: leak.  Do NOT memset -- the slab bytes
	 * belong to whichever entity actually holds LIVE for this
	 * offset, and clobbering them would be the payload-corruption
	 * outcome the whole armour exists to prevent.
	 */
	if (!release_slot(state, off_u, bucket_idx))
		return;

	memset(p, 0, slot_size);
	my_token = (uint32_t)off_u + 1;
	old_tagged = __atomic_load_n(head, __ATOMIC_RELAXED);
	do {
		/* Store only the token half of the previous head into
		 * our slot -- the version stays in the head word. */
		*(uint32_t *)p = (uint32_t)(old_tagged & FREELIST_OFF_MASK);
		new_ver = (uint32_t)(old_tagged >> FREELIST_VER_SHIFT) + 1;
		new_tagged = ((uint64_t)my_token & FREELIST_OFF_MASK) |
			     ((uint64_t)new_ver << FREELIST_VER_SHIFT);
	} while (!__atomic_compare_exchange_n(head, &old_tagged, new_tagged,
					      false,
					      __ATOMIC_RELEASE,
					      __ATOMIC_RELAXED));
}
