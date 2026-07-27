/*
 * Self-checks for utils/shared_freelist.c's bounds AND provenance
 * armour.
 *
 * The primitives run over a caller-owned slab and treat every token
 * (head or slot-link) as fuzzer-writable input, so this suite drives
 * them against a private fake heap:
 *
 *   - freelist_roundtrip:   push a slot, pop it, prove pop returned
 *                           exactly the same address and a zeroed slot,
 *                           and that a second pop finds an empty list.
 *
 *   - freelist_corrupt_head: stomp the head with a wild token (offset
 *                           past the slab, extending past the end, and
 *                           token == UINT32_MAX) and prove pop returns
 *                           NULL without wild-reading -- the fake heap
 *                           is flanked by PROT_NONE guard pages so any
 *                           wild deref/memset would SIGSEGV inside the
 *                           test, not return quietly.
 *
 *   - freelist_corrupt_link: push a valid slot, then stomp its stored
 *                           link with a wild token, and prove pop
 *                           returns the valid slot AND detaches the
 *                           wild chain (the head becomes empty rather
 *                           than pointing into unrelated memory).
 *
 *   - freelist_push_out_of_range: hand freelist_push a pointer that
 *                           isn't inside the slab and prove nothing is
 *                           linked (the head stays sentinel-empty and
 *                           a follow-up pop returns NULL).
 *
 *   - freelist_link_to_live: forge the head with a token that names a
 *                           slot marked LIVE and prove pop refuses to
 *                           re-hand-out the slot (would alias a live
 *                           allocation) even though the token is in
 *                           bounds and slot-start-aligned.
 *
 *   - freelist_cross_bucket: push a slot legitimately onto bucket A's
 *                           free list, then forge the head of bucket
 *                           B with that slot's token and prove B's
 *                           pop refuses -- the state records the slot
 *                           as FREE(A), not FREE(B).
 *
 *   - freelist_interior_offset: forge the head with a token that names
 *                           an aligned interior byte inside a live
 *                           slot and prove pop refuses (state is
 *                           UNCARVED for the interior offset).
 *
 *   - freelist_double_free: push the same slot twice and prove the
 *                           second push is refused -- the state was
 *                           already FREE, not LIVE, so the LIVE->FREE
 *                           CAS fails and the slot is not linked
 *                           twice.  A follow-up alloc/free cycle proves
 *                           the free list is not corrupted (a truncated
 *                           chain from the double-link would surface
 *                           as a wrong-address pop).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "debug.h"			/* BUG */
#include "shared_freelist.h"

#define FAKE_HEAP_CAP		4096U
#define SLOT_SIZE		64U
#define BUCKET_IDX		3U		/* SLOT_SIZE == bucket_sizes[3] */
#define OTHER_BUCKET_IDX	4U		/* != BUCKET_IDX */

_Static_assert(FAKE_HEAP_CAP % SHARED_FREELIST_SLOT_STRIDE == 0,
	       "heap capacity must be a stride multiple for state[] sizing");

struct fake_heap {
	char *guard_lo;			/* PROT_NONE, one page */
	char *base;			/* PROT_READ|WRITE, FAKE_HEAP_CAP */
	char *guard_hi;			/* PROT_NONE, one page */
	size_t page;
	size_t total_bytes;
	uint8_t state[FAKE_HEAP_CAP / SHARED_FREELIST_SLOT_STRIDE];
};

static void fake_heap_init(struct fake_heap *h)
{
	long page_l = sysconf(_SC_PAGESIZE);
	size_t page, heap_pages, total;
	char *region;

	if (page_l <= 0)
		BUG("shared_freelist selftest: sysconf(_SC_PAGESIZE) failed");
	page = (size_t)page_l;
	heap_pages = (FAKE_HEAP_CAP + page - 1) / page;
	total = (heap_pages + 2) * page;

	region = mmap(NULL, total, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED)
		BUG("shared_freelist selftest: mmap of fake heap failed");

	if (mprotect(region, page, PROT_NONE) != 0)
		BUG("shared_freelist selftest: mprotect low guard failed");
	if (mprotect(region + total - page, page, PROT_NONE) != 0)
		BUG("shared_freelist selftest: mprotect high guard failed");

	h->guard_lo	= region;
	h->base		= region + page;
	h->guard_hi	= region + total - page;
	h->page		= page;
	h->total_bytes	= total;
	memset(h->state, 0, sizeof(h->state));

	memset(h->base, 0xa5, FAKE_HEAP_CAP);
}

static void fake_heap_release(struct fake_heap *h)
{
	if (munmap(h->guard_lo, h->total_bytes) != 0)
		BUG("shared_freelist selftest: munmap of fake heap failed");
}

/*
 * Bit-for-bit reconstruction of shared_freelist.c's head encoding.
 * Kept local so a future encoding change trips both this helper and a
 * failing test rather than sliding under a shared macro.
 */
static uint64_t make_head(uint32_t token, uint32_t version)
{
	return ((uint64_t)token & 0xffffffffULL) | ((uint64_t)version << 32);
}

static uint32_t head_token(uint64_t head)
{
	return (uint32_t)(head & 0xffffffffULL);
}

/*
 * Simulate a valid alloc: mark the slot LIVE(bucket) in the state
 * array without touching the freelist head.  The provenance tests use
 * this to reach a "the state authority says this slot is live" setup
 * that a real caller would produce via alloc_shared_str().
 */
static void mark_live(struct fake_heap *h, size_t offset,
		      unsigned int bucket_idx)
{
	h->state[offset / SHARED_FREELIST_SLOT_STRIDE] =
		SHARED_FREELIST_STATE_LIVE(bucket_idx);
}

static void selftest_roundtrip(void)
{
	struct fake_heap heap;
	uint64_t head = 0;
	void *slot, *popped, *empty;
	size_t slot_off;
	unsigned int i;

	fake_heap_init(&heap);

	slot_off = SLOT_SIZE * 3;			/* arbitrary in-slab */
	slot = heap.base + slot_off;
	mark_live(&heap, slot_off, BUCKET_IDX);
	shared_freelist_push(&head, heap.state, BUCKET_IDX, slot,
			     heap.base, FAKE_HEAP_CAP, SLOT_SIZE);

	if (head_token(head) == 0)
		BUG("roundtrip: head still empty after push");

	popped = shared_freelist_pop(&head, heap.state, BUCKET_IDX,
				     heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (popped != slot)
		BUG("roundtrip: pop returned a different address than push");

	for (i = 0; i < SLOT_SIZE; i++) {
		if (((unsigned char *)popped)[i] != 0)
			BUG("roundtrip: pop did not zero the slot");
	}

	empty = shared_freelist_pop(&head, heap.state, BUCKET_IDX,
				    heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (empty != NULL)
		BUG("roundtrip: second pop returned non-NULL from empty list");

	fake_heap_release(&heap);
}

/*
 * Stomp the head with tokens that must NOT be dereferenced: this is
 * the whole point of the armour.  Each case runs on its own fake heap
 * because a failed check would land on the guard pages and abort the
 * process; running them independently keeps the failure signal per-case.
 */
static void selftest_corrupt_head(void)
{
	struct fake_heap heap;
	uint64_t head;
	void *r;

	/* Case 1: token names an offset one past the slab. */
	fake_heap_init(&heap);
	head = make_head((uint32_t)FAKE_HEAP_CAP + 1, 7);
	r = shared_freelist_pop(&head, heap.state, BUCKET_IDX,
				heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (r != NULL)
		BUG("corrupt_head[past-end]: pop dereferenced a wild token");
	fake_heap_release(&heap);

	/* Case 2: token starts inside the slab but slot_size runs past
	 * the end -- the memset would clobber the high guard page. */
	fake_heap_init(&heap);
	head = make_head((uint32_t)(FAKE_HEAP_CAP - (SLOT_SIZE / 2)) + 1, 7);
	r = shared_freelist_pop(&head, heap.state, BUCKET_IDX,
				heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (r != NULL)
		BUG("corrupt_head[straddle]: pop accepted a slot straddling the end");
	fake_heap_release(&heap);

	/* Case 3: token == UINT32_MAX -- maximum wild offset. */
	fake_heap_init(&heap);
	head = make_head(UINT32_MAX, 7);
	r = shared_freelist_pop(&head, heap.state, BUCKET_IDX,
				heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (r != NULL)
		BUG("corrupt_head[max]: pop dereferenced UINT32_MAX token");
	fake_heap_release(&heap);
}

static void selftest_corrupt_link(void)
{
	struct fake_heap heap;
	uint64_t head = 0;
	void *slot, *popped, *empty;
	size_t slot_off;

	fake_heap_init(&heap);

	slot_off = SLOT_SIZE * 5;
	slot = heap.base + slot_off;
	mark_live(&heap, slot_off, BUCKET_IDX);
	shared_freelist_push(&head, heap.state, BUCKET_IDX, slot,
			     heap.base, FAKE_HEAP_CAP, SLOT_SIZE);

	/* Push zeroed the slot and wrote a token-0 link (empty).  Stomp
	 * the link with a wild token -- a naive popper would install
	 * this as the new head and the next pop would dereference it. */
	*(uint32_t *)slot = UINT32_MAX;

	popped = shared_freelist_pop(&head, heap.state, BUCKET_IDX,
				     heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (popped != slot)
		BUG("corrupt_link: pop returned a different address");

	/* The wild link must have been dropped, not installed. */
	if (head_token(head) != 0)
		BUG("corrupt_link: wild link was installed as the new head");

	empty = shared_freelist_pop(&head, heap.state, BUCKET_IDX,
				    heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (empty != NULL)
		BUG("corrupt_link: follow-up pop returned non-NULL");

	fake_heap_release(&heap);
}

static void selftest_push_out_of_range(void)
{
	struct fake_heap heap;
	uint64_t head = 0;
	char *wild;
	void *r;

	fake_heap_init(&heap);

	/* A pointer clearly below the slab (heap.base itself minus one
	 * whole slot).  The negative delta must be refused so we don't
	 * encode it as a very-large positive uint32_t token. */
	wild = heap.base - SLOT_SIZE * 2;
	shared_freelist_push(&head, heap.state, BUCKET_IDX, wild,
			     heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (head_token(head) != 0)
		BUG("push_out_of_range[below]: below-slab pointer was linked");

	/* A pointer beyond the slab. */
	wild = heap.base + FAKE_HEAP_CAP;
	shared_freelist_push(&head, heap.state, BUCKET_IDX, wild,
			     heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (head_token(head) != 0)
		BUG("push_out_of_range[above]: above-slab pointer was linked");

	r = shared_freelist_pop(&head, heap.state, BUCKET_IDX,
				heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (r != NULL)
		BUG("push_out_of_range: pop returned a slot from an empty list");

	fake_heap_release(&heap);
}

/*
 * Provenance: a forged head token that names an in-bounds, aligned,
 * LIVE slot must NOT be re-handed-out.  Pre-armour, pop would return
 * the pointer and the caller would then hold two aliases to the same
 * allocation.
 */
static void selftest_link_to_live(void)
{
	struct fake_heap heap;
	uint64_t head;
	size_t live_off;
	void *r;

	fake_heap_init(&heap);

	live_off = SLOT_SIZE * 7;
	/* Simulate a legitimate alloc having reserved this slot. */
	mark_live(&heap, live_off, BUCKET_IDX);

	/* Forge the head with a token pointing at the live slot -- the
	 * fuzzer-writable head has been stomped to alias this. */
	head = make_head((uint32_t)live_off + 1, 42);

	r = shared_freelist_pop(&head, heap.state, BUCKET_IDX,
				heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (r != NULL)
		BUG("link_to_live: pop handed out a slot marked LIVE");

	/* The state must remain LIVE(BUCKET_IDX) -- the failed CAS is
	 * observation-only and does not clobber the live caller's
	 * ownership. */
	if (heap.state[live_off / SHARED_FREELIST_SLOT_STRIDE] !=
	    SHARED_FREELIST_STATE_LIVE(BUCKET_IDX))
		BUG("link_to_live: failed pop mutated LIVE state");

	fake_heap_release(&heap);
}

/*
 * Provenance: a forged head on bucket B that names a slot legitimately
 * owned by bucket A must NOT be handed out.  The state records FREE(A),
 * and the pop for bucket B expects FREE(B) -- the CAS fails and the
 * slot stays on A's chain.
 */
static void selftest_cross_bucket(void)
{
	struct fake_heap heap;
	uint64_t head_a = 0, head_b;
	size_t slot_off;
	void *slot, *r;

	fake_heap_init(&heap);

	slot_off = SLOT_SIZE * 9;
	slot = heap.base + slot_off;

	/* Legitimately push the slot onto bucket A's chain. */
	mark_live(&heap, slot_off, BUCKET_IDX);
	shared_freelist_push(&head_a, heap.state, BUCKET_IDX, slot,
			     heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (head_token(head_a) == 0)
		BUG("cross_bucket: bucket A push did not link the slot");
	if (heap.state[slot_off / SHARED_FREELIST_SLOT_STRIDE] !=
	    SHARED_FREELIST_STATE_FREE(BUCKET_IDX))
		BUG("cross_bucket: bucket A push did not transition state to FREE(A)");

	/* Forge bucket B's head with A's slot token. */
	head_b = make_head((uint32_t)slot_off + 1, 3);
	r = shared_freelist_pop(&head_b, heap.state, OTHER_BUCKET_IDX,
				heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (r != NULL)
		BUG("cross_bucket: bucket B pop handed out an A-owned slot");

	/* Bucket A still owns the slot -- state must remain FREE(A). */
	if (heap.state[slot_off / SHARED_FREELIST_SLOT_STRIDE] !=
	    SHARED_FREELIST_STATE_FREE(BUCKET_IDX))
		BUG("cross_bucket: failed bucket B pop mutated FREE(A) state");

	/* And a legitimate pop from bucket A must still return the slot. */
	r = shared_freelist_pop(&head_a, heap.state, BUCKET_IDX,
				heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (r != slot)
		BUG("cross_bucket: bucket A lost its slot to a rejected cross-pop");

	fake_heap_release(&heap);
}

/*
 * Provenance: an aligned interior offset inside a live slot must NOT
 * be handed out.  A STRIDE-aligned interior byte has state ==
 * UNCARVED (only slot-start offsets ever get a non-zero record); the
 * CAS from FREE(bucket) fails.  Also cover the non-STRIDE-aligned
 * case, which is rejected up-front before the state CAS.
 */
static void selftest_interior_offset(void)
{
	struct fake_heap heap;
	uint64_t head;
	size_t live_off, interior_off;
	void *r;

	fake_heap_init(&heap);

	live_off = SLOT_SIZE * 11;
	mark_live(&heap, live_off, BUCKET_IDX);

	/* Aligned interior: 8 bytes into the live 64-byte slot.  Still
	 * a multiple of SHARED_FREELIST_SLOT_STRIDE, so alignment
	 * checks pass; state[live_off + STRIDE] is UNCARVED because
	 * only slot starts get recorded. */
	interior_off = live_off + SHARED_FREELIST_SLOT_STRIDE;
	head = make_head((uint32_t)interior_off + 1, 5);
	r = shared_freelist_pop(&head, heap.state, BUCKET_IDX,
				heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (r != NULL)
		BUG("interior_offset[aligned]: pop handed out an interior address");
	if (heap.state[live_off / SHARED_FREELIST_SLOT_STRIDE] !=
	    SHARED_FREELIST_STATE_LIVE(BUCKET_IDX))
		BUG("interior_offset[aligned]: failed pop mutated the covering slot's LIVE state");

	/* Non-STRIDE-aligned: interior_off + 1.  Rejected up-front by
	 * the primitive's alignment check. */
	head = make_head((uint32_t)interior_off + 1 + 1, 5);
	r = shared_freelist_pop(&head, heap.state, BUCKET_IDX,
				heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (r != NULL)
		BUG("interior_offset[misaligned]: pop accepted a non-slot-start token");

	/* Same guard on the push path: a forged free() of an aligned
	 * interior address must not link the interior onto the chain. */
	{
		uint64_t phead = 0;
		char *interior_p = heap.base + interior_off;

		shared_freelist_push(&phead, heap.state, BUCKET_IDX,
				     interior_p, heap.base, FAKE_HEAP_CAP,
				     SLOT_SIZE);
		if (head_token(phead) != 0)
			BUG("interior_offset[push]: interior address was linked");
		if (heap.state[live_off / SHARED_FREELIST_SLOT_STRIDE] !=
		    SHARED_FREELIST_STATE_LIVE(BUCKET_IDX))
			BUG("interior_offset[push]: rejected push mutated LIVE state");
	}

	fake_heap_release(&heap);
}

/*
 * Provenance: pushing the same slot twice (double-free) must be
 * refused on the second push.  Without the state CAS, both pushes
 * would link the slot into the chain; the second link's next-token
 * would point at the first link's payload, and a follow-up pop-pop
 * would return the same address twice -- silent double-hand-out.
 */
static void selftest_double_free(void)
{
	struct fake_heap heap;
	uint64_t head = 0;
	void *slot_a, *slot_b, *popped_a, *popped_b, *empty;
	size_t off_a, off_b;

	fake_heap_init(&heap);

	off_a = SLOT_SIZE * 13;
	off_b = SLOT_SIZE * 14;
	slot_a = heap.base + off_a;
	slot_b = heap.base + off_b;

	/* Legit push A, then legit push B, then a double push of A. */
	mark_live(&heap, off_a, BUCKET_IDX);
	shared_freelist_push(&head, heap.state, BUCKET_IDX, slot_a,
			     heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (heap.state[off_a / SHARED_FREELIST_SLOT_STRIDE] !=
	    SHARED_FREELIST_STATE_FREE(BUCKET_IDX))
		BUG("double_free: first push did not transition A to FREE");

	mark_live(&heap, off_b, BUCKET_IDX);
	shared_freelist_push(&head, heap.state, BUCKET_IDX, slot_b,
			     heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (heap.state[off_b / SHARED_FREELIST_SLOT_STRIDE] !=
	    SHARED_FREELIST_STATE_FREE(BUCKET_IDX))
		BUG("double_free: push of B did not transition B to FREE");

	/* Double-free of A: state is FREE (not LIVE), so release CAS
	 * fails and A is NOT relinked.  Head must still point at B. */
	shared_freelist_push(&head, heap.state, BUCKET_IDX, slot_a,
			     heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (head_token(head) != (uint32_t)off_b + 1)
		BUG("double_free: second push of A relinked and became new head");

	/* Two pops must return distinct slots and drain the chain -- if
	 * the double-free had gone through, the chain would be
	 * A -> A -> B and the first two pops would both return A. */
	popped_a = shared_freelist_pop(&head, heap.state, BUCKET_IDX,
				       heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	popped_b = shared_freelist_pop(&head, heap.state, BUCKET_IDX,
				       heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (popped_a == NULL || popped_b == NULL)
		BUG("double_free: expected two live slots in the chain");
	if (popped_a == popped_b)
		BUG("double_free: chain returned the same slot twice");
	if (!((popped_a == slot_a && popped_b == slot_b) ||
	      (popped_a == slot_b && popped_b == slot_a)))
		BUG("double_free: pops returned unexpected addresses");

	empty = shared_freelist_pop(&head, heap.state, BUCKET_IDX,
				    heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (empty != NULL)
		BUG("double_free: chain not drained after two pops");

	fake_heap_release(&heap);
}

void shared_freelist_self_check(void);
void shared_freelist_self_check(void)
{
	selftest_roundtrip();
	selftest_corrupt_head();
	selftest_corrupt_link();
	selftest_push_out_of_range();
	selftest_link_to_live();
	selftest_cross_bucket();
	selftest_interior_offset();
	selftest_double_free();
}
