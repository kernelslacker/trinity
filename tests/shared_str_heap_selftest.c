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
}
