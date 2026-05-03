/*
 * SYSCALL_DEFINE2(sched_getparam, pid_t, pid, struct sched_param __user *, param)
 */
#include <sched.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_sched_getparam(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, sizeof(struct sched_param));
}

/*
 * Oracle: sched_getparam(pid, &param) copies task->rt_priority (the int
 * scheduling priority maintained by the scheduler core, guarded by
 * task->pi_lock for the RT classes) out to userspace.  When pid == 0 the
 * kernel resolves the target to the calling task, so re-issuing the same
 * query for self gives a second read of the same field through the same
 * code path — the two copies must agree unless something in between
 * either (a) had copy_to_user write past or before the live ->rt_priority
 * field, (b) tore a write from a parallel sched_setparam to current's
 * own param (vanishingly rare for the self-target case), or (c) the
 * userspace receive buffer was clobbered after the kernel returned.
 *
 * Restrict to self (pid == 0 or pid == gettid()): re-calling for some
 * other pid races against that task's own sched_setparam and tells us
 * nothing.  Skip if rec->a2 is NULL — the kernel rejects that with
 * -EFAULT and there is no buffer to compare.  If the re-call itself
 * returns -1 (the original syscall succeeded but the re-call lost a
 * race or the task's sched class changed underneath), give up rather
 * than report a false divergence.  Sample one in a hundred to stay in
 * line with the rest of the oracle family.
 */
static void post_sched_getparam(struct syscallrecord *rec)
{
	struct sched_param local, syscall_buf;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval != 0)
		return;

	if (rec->a1 != 0 && rec->a1 != (unsigned long) gettid())
		return;

	if (rec->a2 == 0)
		return;

	{
		void *param = (void *)(unsigned long) rec->a2;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a2. */
		if (looks_like_corrupted_ptr(param)) {
			outputerr("post_sched_getparam: rejected suspicious param=%p (pid-scribbled?)\n",
				  param);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	memset(&local, 0, sizeof(local));
	if (sched_getparam(0, &local) == -1)
		return;

	memcpy(&syscall_buf, (struct sched_param *)(unsigned long) rec->a2,
	       sizeof(syscall_buf));

	if (local.sched_priority != syscall_buf.sched_priority) {
		output(0, "sched_getparam oracle: syscall=%d but recheck=%d\n",
		       syscall_buf.sched_priority, local.sched_priority);
		__atomic_add_fetch(&shm->stats.sched_getparam_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_sched_getparam = {
	.name = "sched_getparam",
	.group = GROUP_SCHED,
	.num_args = 2,
	.argtype = { [0] = ARG_PID, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "pid", [1] = "param" },
	.sanitise = sanitise_sched_getparam,
	.rettype = RET_ZERO_SUCCESS,
	.post = post_sched_getparam,
};
