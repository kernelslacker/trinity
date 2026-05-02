/*
 * SYSCALL_DEFINE1(sched_getscheduler, pid_t, pid)
 */
#include <sched.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Oracle: sched_getscheduler(pid) reads the target task's scheduling
 * policy from task_struct->policy (the SCHED_* enum maintained by the
 * scheduler core / sched_class).  When pid == 0 the kernel resolves the
 * target to the calling task, so we can re-issue the same query and the
 * two reads must agree — the calling task's own policy cannot change
 * underneath us between the syscall and the libc wrapper unless
 * something else (a sched_setscheduler from another thread, a torn
 * write to ->policy, or a stale rcu task lookup) raced with us.
 *
 * Restrict to pid == 0: querying any other pid races against that
 * task's own scheduler updates and tells us nothing.  Skip failures
 * (retval < 0): -1/errno means no policy was returned, so there is
 * nothing to compare.  Sample one in a hundred to stay in line with
 * the rest of the oracle family.
 */
static void post_sched_getscheduler(struct syscallrecord *rec)
{
	int current_policy;

	if (rec->a1 != 0)
		return;
	if ((long) rec->retval < 0)
		return;
	if (!ONE_IN(100))
		return;

	current_policy = sched_getscheduler(0);
	if (current_policy != (int) rec->retval) {
		output(0, "sched oracle: sched_getscheduler(0) returned %d but rec->retval was %ld\n",
		       current_policy, (long) rec->retval);
		__atomic_add_fetch(&shm->stats.sched_getscheduler_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_sched_getscheduler = {
	.name = "sched_getscheduler",
	.group = GROUP_SCHED,
	.num_args = 1,
	.argtype = { [0] = ARG_PID },
	.argname = { [0] = "pid" },
	.rettype = RET_ZERO_SUCCESS,
	.post = post_sched_getscheduler,
};
