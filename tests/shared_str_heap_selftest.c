/*
 * shared_str_heap_free_size_check
 * -------------------------------
 *
 * Regression suite for the free-size authority in utils/shared_str_heap.c.
 *
 * The bug it pins:
 *
 *   alloc_shared_str() carves size-classed slots from a MAP_SHARED
 *   region and pushes them back onto per-bucket freelists on free.
 *   If free_shared_str() picks its target bucket by re-strlen()'ing
 *   the payload -- which lives in memory the fuzzer can scribble via
 *   a syscall user pointer -- a stomped terminating NUL turns the
 *   free size into an attacker-controlled quantity.  A NUL wiped
 *   entirely runs strlen() past the slot end into adjacent live
 *   payloads, returning a length that maps to a LARGER bucket than
 *   alloc carved.  The subsequent freelist push memsets the wrong
 *   number of bytes past the slot, and the next pop hands a too-
 *   small chunk out as if it were the larger bucket's slot -- silent
 *   scribble class.
 *
 *   The fix records the bucket at alloc time in a metadata table
 *   living outside the fuzz-exposed heap; free_shared_str() reads
 *   the recorded bucket instead of re-deriving one from the payload.
 *   The size parameter passed to free_shared_str() is thus advisory
 *   for any slot alloc has tracked.
 *
 * Suite shape (targets every bucket in [1, 1024]):
 *
 *   For each bucket:
 *     1. Prime an adjacent "spam" slot filled with a non-NUL byte so
 *        the target slot's neighbour holds no zero for strlen() to
 *        stop on.
 *     2. Alloc the target at a size that lands in this bucket.
 *     3. Fill the entire target slot with the same non-NUL byte to
 *        stomp the terminating NUL alloc_shared_str() zero-init
 *        left behind.
 *     4. Call free_shared_str() with a strlen()-derived size --
 *        exactly the pattern the maps destructor uses.  strlen()
 *        over-reads through target + spam and returns a length that
 *        rounds up to a bucket well past the target's actual
 *        bucket (or off the top of every bucket entirely for the
 *        larger targets).
 *     5. Alloc the same size again; assert the returned pointer is
 *        the target pointer.  Because each bucket contains exactly
 *        one slot at this point (the target we just freed), a same-
 *        bucket pop returns the same address the freelist head was
 *        installed with.  A wrong-bucket free (unpatched) leaves the
 *        correct bucket empty and forces a fresh bump alloc, which
 *        returns a different address -- the assertion fires and the
 *        test binary exits non-zero.
 *
 * Determinism: no RNG use, no /proc reads, no clock reads.  The
 * heap is freshly re-mapped at the top of the suite via
 * shared_str_heap_reset_for_test() so a prior test's residue cannot
 * skew the "same pointer comes back" check.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared_freelist.h"
#include "shared_str_heap.h"
#include "utils-mem.h"

/*
 * One entry per bucket.  alloc_size lands in the target bucket after
 * alloc_shared_str's 8-byte round-up:
 *   1 -> 8   (bucket 0)
 *   9 -> 16  (bucket 1)
 *   17 -> 32 (bucket 2)
 *   33 -> 64 (bucket 3)
 *   65 -> 128 (bucket 4)
 *   129 -> 256 (bucket 5)
 *   257 -> 512 (bucket 6)
 *   513 -> 1024 (bucket 7)
 */
struct bucket_case {
	size_t alloc_size;
	size_t bucket_bytes;
};

static const struct bucket_case cases[] = {
	{ 1,   8    },
	{ 9,   16   },
	{ 17,  32   },
	{ 33,  64   },
	{ 65,  128  },
	{ 129, 256  },
	{ 257, 512  },
	{ 513, 1024 },
};

static void fail(const char *msg, size_t alloc_size, void *expected,
		 void *got)
{
	fprintf(stderr,
		"shared_str_heap_free_size_check: %s (alloc_size=%zu, "
		"expected slot=%p, got=%p)\n",
		msg, alloc_size, expected, got);
	fflush(stderr);
	abort();
}

/* =====================================================================
 * Cases 1-4 below are additional free_shared_str() fixtures.
 *
 * Cases 1-3 are regression assertions for the 374·A fix: they verify
 * that free_shared_str() range/alignment/slot_state-gates the pointer
 * and skips any memset for non-LIVE slots.  Case 4 is a full
 * alloc/free/realloc round-trip across every size bucket.
 * ===================================================================== */

/*
 * CASE 1: duplicate free must leave the freelist chain intact.
 *
 * After a slot is freed correctly its first four bytes hold the
 * next-token link for the freelist chain.  free_shared_str() must
 * recognise FREE(bucket) state and skip the memset so the link is
 * not clobbered by a double-free.
 *
 * Assertion: the first four bytes of the freed slot (its next-chain
 * link) are identical before and after the second free call.
 */
static void xfail_double_free_chain(void)
{
	char *slot_a, *slot_b;
	uint32_t link_before, link_after;

	shared_str_heap_reset_for_test();

	/* Two bucket-0 (8-byte) allocations from a fresh heap.
	 * Bump order gives slot_a at offset 0, slot_b at offset 8. */
	slot_a = alloc_shared_str(1);
	slot_b = alloc_shared_str(1);
	if (!slot_a || !slot_b)
		fail("double_free_chain: alloc failed", 8, NULL, NULL);

	/* Build chain slot_a -> slot_b -> nil.
	 * Free slot_b first so its next-token is 0 (empty),
	 * then free slot_a so its next-token points at slot_b. */
	free_shared_str(slot_b, 8);
	free_shared_str(slot_a, 8);
	/* slot_a[0..3] now holds the token (offset+1) of slot_b. */
	memcpy(&link_before, slot_a, sizeof(link_before));

	/* Second free of slot_a.  State at slot_a is FREE(0), which
	 * is NOT in the LIVE range, so free_shared_str() falls through
	 * to memset(slot_a, 0, 8) and clobbers the link. */
	free_shared_str(slot_a, 8);
	memcpy(&link_after, slot_a, sizeof(link_after));

	if (link_after != link_before)
		fail("double_free_chain: freelist link clobbered by second free",
		     8, (void *)(uintptr_t)link_before, (void *)(uintptr_t)link_after);
	fprintf(stderr, "case 1 (double_free_chain): PASS\n");
}

/*
 * CASE 2: free of a stride-aligned interior pointer must not corrupt
 * the enclosing live allocation.
 *
 * free_shared_str() must recognise that a stride-aligned address
 * falling inside a live slot has state UNCARVED (not LIVE at that
 * index) and skip any memset rather than scribbling the live payload.
 *
 * Assertion: bytes at the interior stride offset are byte-identical
 * before and after the bogus free call.
 */
static void xfail_interior_ptr_corruption(void)
{
	char *big;
	char before_buf[SHARED_FREELIST_SLOT_STRIDE];
	char after_buf[SHARED_FREELIST_SLOT_STRIDE];

	shared_str_heap_reset_for_test();

	/* Bucket 3: alloc_size 33 rounds to 64-byte slot.
	 * slot_state[off/STRIDE] = LIVE(3) for the slot start only;
	 * slot_state[(off + STRIDE)/STRIDE] = 0 (UNCARVED) for +8. */
	big = alloc_shared_str(33);
	if (!big)
		fail("interior_ptr_corruption: alloc failed",
		     33, NULL, NULL);

	/* Fill the whole slot so the interior stride unit is non-zero. */
	memset(big, 'M', 64);
	memcpy(before_buf, big + SHARED_FREELIST_SLOT_STRIDE,
	       sizeof(before_buf));

	/* Free the stride-aligned interior address big + STRIDE.
	 * It is in-slab, STRIDE-aligned, but state is UNCARVED (0),
	 * so free_shared_str() falls through and issues
	 * memset(big + STRIDE, 0, STRIDE), corrupting the live slot. */
	free_shared_str(big + SHARED_FREELIST_SLOT_STRIDE,
			SHARED_FREELIST_SLOT_STRIDE);
	memcpy(after_buf, big + SHARED_FREELIST_SLOT_STRIDE,
	       sizeof(after_buf));

	if (memcmp(before_buf, after_buf, sizeof(before_buf)) != 0)
		fail("interior_ptr_corruption: live slot bytes modified by "
		     "free of interior stride pointer",
		     SHARED_FREELIST_SLOT_STRIDE,
		     big + SHARED_FREELIST_SLOT_STRIDE, NULL);
	fprintf(stderr, "case 2 (interior_ptr_corruption): PASS\n");
}

/*
 * CASE 3: free of a never-carved in-heap pointer must be a no-op.
 *
 * free_shared_str() of a stride-aligned offset whose slot_state is
 * UNCARVED (never allocated, past the bump cursor) must skip the
 * memset entirely rather than writing into never-used heap space.
 *
 * Assertion: every byte in the target range retains its sentinel
 * value after the bogus free call.
 */
static void xfail_uncarved_ptr_write(void)
{
	char *slot_a, *uncarved;
	unsigned int i;

	shared_str_heap_reset_for_test();

	/* Alloc one bucket-0 slot to initialise the heap; bump cursor
	 * lands at STRIDE.  The next stride-aligned address (slot_a +
	 * STRIDE) is inside the mmap'd region but was never carved. */
	slot_a = alloc_shared_str(1);
	if (!slot_a)
		fail("uncarved_ptr_write: alloc failed", 1, NULL, NULL);

	uncarved = slot_a + SHARED_FREELIST_SLOT_STRIDE;

	/* Prime with a non-zero sentinel so a spurious memset is
	 * detectable: if free_shared_str() is a no-op the bytes
	 * survive; if it issues memset() they become 0. */
	memset(uncarved, 'P', SHARED_FREELIST_SLOT_STRIDE);

	/* Bogus free: uncarved is stride-aligned, inside the heap,
	 * state == UNCARVED (0) -- should be a no-op; is not at HEAD. */
	free_shared_str(uncarved, SHARED_FREELIST_SLOT_STRIDE);

	for (i = 0; i < SHARED_FREELIST_SLOT_STRIDE; i++) {
		if ((unsigned char)uncarved[i] != 'P')
			fail("uncarved_ptr_write: free_shared_str() wrote to "
			     "never-carved heap (UNCARVED slot not gated)",
			     SHARED_FREELIST_SLOT_STRIDE, uncarved, NULL);
	}
	fprintf(stderr, "case 3 (uncarved_ptr_write): PASS\n");
}

/*
 * CASE 4 (EXPECTED TO PASS at HEAD): alloc/free/realloc round-trip
 * across every one of the 8 size buckets.
 *
 * For each bucket: allocate a slot at the bucket's canonical size,
 * fill it with a per-bucket sentinel byte, free it, then re-allocate
 * the same size.  The re-alloc MUST return the exact same pointer
 * (the freelist held exactly one slot -- the one we freed -- so a
 * correct-bucket pop returns it).  The returned slot MUST be zeroed
 * by the freelist pop's memset.  After freeing each slot the sibling
 * buckets' freelists must remain unaffected (no cross-bucket
 * leakage).
 */
static void pass_bucket_roundtrip(void)
{
	unsigned int i;

	shared_str_heap_reset_for_test();

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		size_t alloc_size   = cases[i].alloc_size;
		size_t bucket_bytes = cases[i].bucket_bytes;
		char *slot, *slot2;
		unsigned int j;

		slot = alloc_shared_str(alloc_size);
		if (slot == NULL)
			fail("pass_bucket_roundtrip: initial alloc failed",
			     alloc_size, NULL, NULL);

		/* Fill with a per-bucket sentinel so a stale-slot pop
		 * (wrong bucket) would return non-zero bytes. */
		memset(slot, (int)('A' + i), bucket_bytes);

		/* Free and immediately re-alloc the same size: with one
		 * slot in the freelist the pop MUST return the same addr. */
		free_shared_str(slot, bucket_bytes);

		slot2 = alloc_shared_str(alloc_size);
		if (slot2 == NULL)
			fail("pass_bucket_roundtrip: re-alloc returned NULL "
			     "(freelist empty -- wrong-bucket free?)",
			     alloc_size, slot, NULL);
		if (slot2 != slot)
			fail("pass_bucket_roundtrip: wrong-bucket free "
			     "(re-alloc did not recycle the freed slot)",
			     alloc_size, slot, slot2);

		/* Freelist pop zeroes the slot on success. */
		for (j = 0; j < bucket_bytes; j++) {
			if (slot2[j] != 0)
				fail("pass_bucket_roundtrip: slot not zeroed "
				     "after freelist pop",
				     alloc_size, slot, slot2);
		}

		/* Return slot2 to the freelist so it is empty entering
		 * the next iteration (cross-bucket contamination check). */
		free_shared_str(slot2, bucket_bytes);

		/* Cross-bucket leakage check: alloc this bucket's size
		 * once more; we should get slot back (it is the only slot
		 * on this bucket's freelist).  If a cross-bucket push
		 * occurred, the pop would return something else or NULL. */
		slot = alloc_shared_str(alloc_size);
		if (slot == NULL)
			fail("pass_bucket_roundtrip: cross-bucket check alloc "
			     "returned NULL",
			     alloc_size, slot2, NULL);
		if (slot != slot2)
			fail("pass_bucket_roundtrip: cross-bucket leakage "
			     "(unexpected pointer on freelist)",
			     alloc_size, slot2, slot);

		/* Leave the slot allocated so subsequent bucket iterations
		 * have a clean freelist for their own round-trip. */
	}
}

void shared_str_heap_free_size_check(void);

void shared_str_heap_free_size_check(void)
{
	unsigned int i;

	/* Fresh heap: prior tests (or a rerun in the same process) must
	 * not leave residue that would let the "same pointer comes
	 * back" check pass by accident. */
	shared_str_heap_reset_for_test();

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		size_t alloc_size = cases[i].alloc_size;
		size_t bucket_bytes = cases[i].bucket_bytes;
		char *spam_pre, *target, *spam_post, *target2;
		size_t strlen_free_size;

		/* Prime the offset just before the target with a
		 * non-NUL-terminated buffer so a strlen() from the
		 * target -- once its own NUL is stomped -- has nowhere
		 * to stop nearby. */
		spam_pre = alloc_shared_str(1024);
		if (spam_pre == NULL)
			fail("spam_pre alloc failed", alloc_size, NULL, NULL);
		memset(spam_pre, 'X', 1024);

		target = alloc_shared_str(alloc_size);
		if (target == NULL)
			fail("target alloc failed", alloc_size, NULL, NULL);

		/* Bump another spam slot AFTER the target so strlen()
		 * over-reads through 1024 non-NUL bytes past the target
		 * -- guaranteeing a strlen-derived free size that lands
		 * in a different bucket than the target's own. */
		spam_post = alloc_shared_str(1024);
		if (spam_post == NULL)
			fail("spam_post alloc failed", alloc_size, NULL, NULL);
		memset(spam_post, 'X', 1024);

		/* Stomp the target's terminating NUL: fill the whole
		 * slot with a non-NUL byte so strlen() reads past the
		 * slot boundary. */
		memset(target, 'X', bucket_bytes);

		/* This is the vulnerable free pattern from mm/maps-
		 * lifecycle.c: strlen(map->name) + 1 as the free size.
		 * Under the fix the recorded bucket wins and this size
		 * is ignored; unpatched, it lands the free in the
		 * wrong bucket (or the leak path for the larger
		 * targets, which over-shoot all buckets). */
		strlen_free_size = strlen(target) + 1;
		free_shared_str(target, strlen_free_size);

		/* Alloc the same size again.  The target's bucket
		 * freelist now holds exactly one slot -- the target we
		 * just freed -- so a correct-bucket pop returns the
		 * same address.  Any other outcome means free landed
		 * in a different bucket (or leaked) and this alloc had
		 * to bump-carve a fresh slot. */
		target2 = alloc_shared_str(alloc_size);
		if (target2 == NULL)
			fail("re-alloc failed", alloc_size, target, NULL);
		if (target2 != target)
			fail("free lost the slot -- wrong bucket",
			     alloc_size, target, target2);
	}

	/* === four additional free_shared_str() corruption cases === */

	/* Cases 1-3: regression assertions for the 374·A fix. */
	xfail_double_free_chain();
	xfail_interior_ptr_corruption();
	xfail_uncarved_ptr_write();

	/* Case 4: expected to PASS at HEAD. */
	pass_bucket_roundtrip();
}
