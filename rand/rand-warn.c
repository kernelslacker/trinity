/*
 * Runtime tripwire for libc rand().
 *
 * scripts/check-static/no-libc-rand.sh is a build-time grep that
 * rejects new rand() / random() / *rand48() callsites outside rand/
 * and include/rnd.h.  It can only inspect source files in the tree,
 * so a rand() pulled in by a macro expansion from a system or third-
 * party header, or via a transitively included header the static
 * walker does not visit, would slip through unnoticed.  This file
 * provides the runtime catch for that residual blind spot.
 *
 * Mechanism: -Wl,--wrap=rand (set in the Makefile) redirects every
 * call to rand() in the final link to __wrap_rand below, and exposes
 * the real libc entry point as __real_rand.  The wrapper prints one
 * outputerr line the first time it fires in any given process (an
 * atomic flag guards against concurrent first-hits double-printing)
 * and then forwards to libc so behaviour is unchanged.
 *
 * Each fork()ed child inherits its own copy of the flag, so a callsite
 * that fires once per child still produces one warning line per child,
 * which is what we want for narrowing down where the call originates.
 *
 * srand() is intentionally not wrapped: the parent legitimately calls
 * it from init_seed() / set_seed() in rand/seed.c to keep the seed-
 * reproduction story working for the rand() callers that have not yet
 * been migrated to rnd_u32() / rnd_u64() / rnd_modulo_u32().
 */
#include <stdatomic.h>
#include "trinity.h"

extern int __real_rand(void);

int __wrap_rand(void);
int __wrap_rand(void)
{
	static atomic_flag warned = ATOMIC_FLAG_INIT;

	if (!atomic_flag_test_and_set_explicit(&warned, memory_order_relaxed)) {
		outputerr("WARNING: libc rand() called at runtime (caller=%p) "
			  "-- use rnd_u32() / rnd_u64() from include/rnd.h "
			  "instead.\n",
			  __builtin_return_address(0));
	}

	return __real_rand();
}
