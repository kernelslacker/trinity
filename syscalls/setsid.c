/*
 * SYSCALL_DEFINE0(setsid)
 */
#include <sys/types.h>
#include <unistd.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Oracle: setsid() on success creates a new session whose session id equals
 * the calling task's pid (in the caller's pid namespace) and makes the caller
 * the session+process-group leader.  The kernel side flips
 * task->signal->pids[PIDTYPE_SID] (and PIDTYPE_PGID) to the task's own pid
 * struct, then returns pid_vnr(task_session(current)) — which by construction
 * is the same value getsid(0) will subsequently report.  Re-calling getsid(0)
 * on the same task right after setsid() returns therefore exercises the same
 * task_session()/pid_vnr() path the syscall just wrote, but as a fresh read,
 * so a divergence between rec->retval and the re-read is its own corruption
 * shape: a torn write to signal->pids[PIDTYPE_SID], a stale rcu pointer to
 * signal_struct, or a mismatched pid_ns translation between the two reads.
 * Mirror of the getsid self-recheck oracle, applied to the writer side.
 *
 * Skip when retval == -1 (setsid failed, typically EPERM because the caller
 * was already a process-group leader; nothing to validate).
 */
static void post_setsid(struct syscallrecord *rec)
{
	pid_t got, recheck;

	if (!ONE_IN(100))
		return;

	got = (pid_t) rec->retval;
	if (got == (pid_t)-1)
		return;

	recheck = getsid(0);
	if (recheck == (pid_t)-1)
		return;

	if (recheck != got) {
		output(0, "setsid oracle: setsid()=%d but "
		       "subsequent getsid(0)=%d\n", got, recheck);
		__atomic_add_fetch(&shm->stats.setsid_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_setsid = {
	.name = "setsid",
	.group = GROUP_PROCESS,
	.num_args = 0,
	.rettype = RET_PID_T,
	.post = post_setsid,
};
