/*
 * Self-check for the writable-pool exemption in asb_relocate(), reached
 * through avoid_shared_buffer_out(): a range wholly inside the pool is
 * left where it is, and any other range the overlap predicates flag is
 * moved into it, one whose end wraps the address space included.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>

#include "arch.h"		/* page_size */
#include "debug.h"		/* BUG */
#include "sanitise.h"		/* writable pool, avoid_shared_buffer_out */
#include "utils-macros.h"	/* ARRAY_SIZE */

extern bool fake_overlaps_shared;	/* fake_shm.c */

static char outside[64];

struct asb_case {
	const char *what;
	unsigned long addr;
	unsigned long len;
	bool moved;
};

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
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
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

void asb_relocate_self_check(void);
void asb_relocate_self_check(void)
{
	unsigned long base;

	/* The pool is made once per process: take it as an earlier suite
	 * left it.  A request for all of it can only start at its base. */
	base = (unsigned long) get_writable_address(WRITABLE_POOL_BYTES);
	if (base == 0) {
		writable_pool_init();
		base = (unsigned long) get_writable_address(WRITABLE_POOL_BYTES);
	}

	/* Every range above overlaps something tracked, as the pool itself
	 * does in a run and a range that wraps does by definition. */
	fake_overlaps_shared = true;
	pool_exemption(base);
	fake_overlaps_shared = false;
}
