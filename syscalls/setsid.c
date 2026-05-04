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

	/*
	 * Kernel ABI: setsid on success returns pid_vnr(task_session(current))
	 * which equals the calling task's pid in the caller's pid_ns (the kernel
	 * just made the caller the session leader), so the value is bounded by
	 * PID_MAX_LIMIT (4194304) and is always >= 1. Failure returns -1UL
	 * (typically EPERM when the caller is already a process-group leader).
	 * Anything outside [1, PID_MAX_LIMIT] ∪ {-1UL} is a corrupted retval
	 * (sign-extension tear, pid_ns translation bug, or torn write to
	 * signal->pids[PIDTYPE_SID]) — reject on every call before the
	 * ONE_IN(100) re-read oracle below, since that gate would only catch
	 * such corruption ~1% of the time.
	 */
	if (rec->retval != (unsigned long)-1L &&
	    (rec->retval == 0 || rec->retval > 4194304UL)) {
		output(0, "post_setsid: rejected returned sid 0x%lx outside [1, PID_MAX_LIMIT=4194304] (and not -1)\n",
		       rec->retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}

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
