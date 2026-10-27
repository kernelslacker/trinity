/*
 * Self-check for the writable-pool exemption in asb_relocate(), reached
 * through avoid_shared_buffer_out(): a range wholly inside the pool stays,
 * any other flagged range moves into it (one whose end wraps the address
 * space included), and a length the pool cannot hold leaves the pointer.
 * get_writable_address() refuses such a size, a wrapping round-up included.
 * A pointer that starts in the low pool, a compat call's, stays too.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>

#include "arch.h"		/* page_size */
#include "child.h"		/* struct childdata */
#include "debug.h"		/* BUG */
#include "sanitise.h"		/* writable and low pools, avoid_shared_buffer_out */
#include "utils-macros.h"	/* ARRAY_SIZE */

extern bool fake_overlaps_shared;	/* fake_shm.c */
extern struct childdata *fake_this_child;	/* fake_shm.c */

static char outside[64];

struct asb_case {
	const char *what;
	unsigned long addr;
	unsigned long len;
	bool moved;
};

/* Each case's pointer moves only if it should, and only into the writable
 * pool. */
static void run_cases(const struct asb_case *cases, unsigned int nr)
{
	unsigned int i;

	for (i = 0; i < nr; i++) {
		const struct asb_case *c = &cases[i];
		unsigned long addr = c->addr;

		avoid_shared_buffer_out(&addr, c->len);

		if ((addr != c->addr) != c->moved) {
			fprintf(stderr, "%s: %s\n", c->what,
				c->moved ? "left where it was" : "moved");
			BUG("asb_relocate: wrong verdict on the pool test");
		}
		if (c->moved &&
		    !range_in_writable_pool(addr, c->len ? c->len : page_size)) {
			fprintf(stderr, "%s: moved to %#lx, outside the pool\n",
				c->what, addr);
			BUG("asb_relocate: a range moved out of the pool");
		}
	}
}

static void pool_exemption(unsigned long base)
{
	const unsigned long end = base + WRITABLE_POOL_BYTES;
	const struct asb_case cases[] = {
		/* Adding len to a wild pointer near the top of the address
		 * space wraps to a small number, which a test that adds
		 * takes for a range inside the pool. */
		{ "a range wrapping the address space",
		  ULONG_MAX - 7, 16, true },
		{ "an all-ones pointer",
		  ULONG_MAX, page_size, true },

		/* Wholly inside the pool, to its last byte. */
		{ "the middle of the pool", base + 4096, 64, false },
		{ "the last bytes of the pool", end - 64, 64, false },
		{ "the whole pool", base, WRITABLE_POOL_BYTES, false },

		/* Not wholly inside it. */
		{ "a range running a byte past the pool end",
		  end - 64, 65, true },
		{ "a range starting below the pool", base - 64, 64, true },
		{ "a range outside the pool",
		  (unsigned long) outside, sizeof(outside), true },

		/* With no length the pointer alone decides. */
		{ "no length, in the pool", base + 4096, 0, false },
		{ "no length, at the pool base", base, 0, false },
		{ "no length, at the last byte of the pool", end - 1, 0, false },
		{ "no length, outside the pool",
		  (unsigned long) outside, 0, true },

		/* A length the pool cannot hold has no slot to move the
		 * pointer to.  One above ULONG_MAX - 15 rounds up to zero,
		 * which is no reason to give it an empty one. */
		{ "a length a byte longer than the pool",
		  (unsigned long) outside, WRITABLE_POOL_BYTES + 1, false },
		{ "a length whose round-up wraps to zero",
		  (unsigned long) outside, ULONG_MAX - 14, false },
		{ "an all-ones length",
		  (unsigned long) outside, ULONG_MAX, false },
	};

	run_cases(cases, ARRAY_SIZE(cases));
}

/* A compat call's buffer comes from the low pool, and a writable pool
 * replacement would reach its kernel cut to 32 bits, so a pointer that
 * starts in the low pool stays however far its range runs: the pool ends
 * at a guard page.  One that starts outside it moves, as before. */
static void low_pool_exemption(unsigned long base)
{
	const unsigned long end = base + WRITABLE_POOL_BYTES;
	const struct asb_case cases[] = {
		{ "the low pool's start", base, 64, false },
		{ "a range running past the low pool's end",
		  end - 64, 2 * page_size, false },
		{ "no length, at the low pool's last byte", end - 1, 0, false },
		{ "a range starting below the low pool", base - 64, 64, true },
		{ "a range starting at the low pool's end", end, 64, true },
	};

	run_cases(cases, ARRAY_SIZE(cases));
}

/* The sizes either side of the one whose round-up to the 16-byte slot
 * alignment wraps to zero, which passes a pool-size test made after the
 * rounding. */
static void oversize_refused(void)
{
	static const struct {
		const char *what;
		unsigned long size;
	} cases[] = {
		{ "a byte more than the pool", WRITABLE_POOL_BYTES + 1 },
		{ "the largest size that rounds up without wrapping",
		  ULONG_MAX - 15 },
		{ "the smallest size that rounds up to zero", ULONG_MAX - 14 },
		{ "ULONG_MAX - 1", ULONG_MAX - 1 },
		{ "ULONG_MAX", ULONG_MAX },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		if (get_writable_address(cases[i].size) != NULL) {
			fprintf(stderr, "%s: got a slot\n", cases[i].what);
			BUG("get_writable_address: slot for a size the pool cannot hold");
		}
	}
}

void asb_relocate_self_check(void);
void asb_relocate_self_check(void)
{
	static struct childdata compat;
	unsigned long base, low;

	/* The pool is made once per process: take it as an earlier suite
	 * left it.  A request for all of it can only start at its base. */
	base = (unsigned long) get_writable_address(WRITABLE_POOL_BYTES);
	if (base == 0) {
		writable_pool_init();
		base = (unsigned long) get_writable_address(WRITABLE_POOL_BYTES);
	}

	/* Likewise for the low pool, which test_main made and a compat
	 * call's buffers come from; an arch with no compat calls has none. */
	compat.syscall.do32bit = true;
	fake_this_child = &compat;
	low = (unsigned long) get_writable_address(WRITABLE_POOL_BYTES);
	fake_this_child = NULL;

	/* Every range above overlaps something tracked, as the pool itself
	 * does in a run and a range that wraps does by definition. */
	fake_overlaps_shared = true;
	pool_exemption(base);
	if (low != 0)
		low_pool_exemption(low);
	fake_overlaps_shared = false;

	oversize_refused();
}
