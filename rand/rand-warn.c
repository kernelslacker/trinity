/*
 * Runtime tripwire for libc rand().  no-libc-rand.sh (check-static) only
 * greps source files, so a rand() pulled in by a macro expansion or an
 * unvisited header slips past it; -Wl,--wrap=rand (set in the Makefile)
 * routes every such call here, where it warns once and forwards.  Nothing
 * seeds libc's generator, so a call that reaches here ignores -s: a bug.
 */
#include <stdatomic.h>
#include "trinity.h"

extern int __real_rand(void);

int __wrap_rand(void);
int __wrap_rand(void)
{
	/* One warning per process, and a test-and-set so concurrent first
	 * hits cannot double-print.  A forked child inherits its own copy, so
	 * a callsite that fires once per child warns once per child, which
	 * narrows down where the call originates. */
	static atomic_flag warned = ATOMIC_FLAG_INIT;

	if (!atomic_flag_test_and_set_explicit(&warned, memory_order_relaxed)) {
		outputerr("WARNING: libc rand() called at runtime (caller=%p) "
			  "-- use rnd_u32() / rnd_u64() from include/rnd.h "
			  "instead.\n",
			  __builtin_return_address(0));
	}

	return __real_rand();
}
