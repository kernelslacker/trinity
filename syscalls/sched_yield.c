/*
 * SYSCALL_DEFINE0(sched_yield)
 */
#include "shm.h"
#include "random.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Oracle: sys_sched_yield is documented to "always succeed" and the
 * kernel implementation in kernel/sched/syscalls.c hard-codes a
 * `return 0;` after the yield.  That zero return is part of the
 * userspace ABI -- man 2 sched_yield states the call cannot fail and
 * countless runtimes (glibc's pthread spin paths, JVMs, Go's
 * runtime, libuv, etc.) treat the return as unconditional success
 * without bothering to check.  Any silent kernel re-mapping that
 * propagates a non-zero value -- a refactor that returns an errno
 * instead of zero, a torn write of the return slot, or a new
 * scheduler class that forgets to clear the return -- would break
 * every consumer that ignores the result.
 *
 * The oracle is the cheapest possible: no second syscall, no /proc
 * parse, no policy lookup.  The contract IS the constant 0, so a
 * direct compare against rec->retval is sufficient.  Sample one in a
 * hundred to stay in line with the rest of the oracle family.
 */
static void post_sched_yield(struct syscallrecord *rec)
{
	if (!ONE_IN(100))
		return;

	if (rec->retval != 0) {
		output(0, "sched_yield oracle: returned %ld but expected 0\n",
		       (long) rec->retval);
		__atomic_add_fetch(&shm->stats.sched_yield_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_sched_yield = {
	.name = "sched_yield",
	.group = GROUP_SCHED,
	.num_args = 0,
	.post = post_sched_yield,
};
