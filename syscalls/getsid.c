/*
 * SYSCALL_DEFINE1(getsid, pid_t, pid)
 */
#include <sys/types.h>
#include <unistd.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * Oracle: getsid(0) returns the session id of the calling task in the
 * caller's pid namespace.  /proc/self/status doesn't expose the session id
 * directly (it's a field in /proc/self/stat, which is fragile to parse
 * because comm can contain whitespace and parentheses), so the cleanest
 * second view is just to re-call getsid(0) and compare.  Both calls walk the
 * same task_struct via pid_vnr(task_session(current)) but at different
 * points in time, so a divergence between the syscall return and a
 * subsequent re-read of the same task's session is its own corruption
 * shape: stale rcu pointer to signal_struct, torn write to session pid, or
 * a bogus pid_ns translation between the two reads.  Mirror of the
 * getuid/getgid/getppid oracle stack.
 *
 * If the caller passed a non-zero pid arg, the syscall queried some other
 * task — we can only validate self-session this way, so skip.
 */
static void post_getsid(struct syscallrecord *rec)
{
	pid_t got, recheck;

	/*
	 * Kernel ABI: success retval is pid_vnr(task_session(current)) — a
	 * positive vpid in [1, PID_MAX_LIMIT=4194304] bounded by the caller's
	 * pid_ns. Failure returns -1UL (errno style on the syscall return
	 * path). Anything else is a corrupted retval (sign-extension tear,
	 * pid_ns translation bug returning -errno, or a torn read of
	 * task_session(current)->numbers[].nr) — reject before the procfs/
	 * re-call oracle's 1-in-100 sample, which would otherwise miss it
	 * 99% of the time.
	 */
	if (rec->retval != (unsigned long)-1L &&
	    (rec->retval < 1 || rec->retval > 4194304UL)) {
		output(0, "post_getsid: rejected returned sid 0x%lx outside [1, PID_MAX_LIMIT=4194304] (and not -1)\n",
		       rec->retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}

	if (!ONE_IN(100))
		return;

	if (rec->a1 != 0)
		return;

	got = (pid_t) rec->retval;
	if (got == (pid_t)-1)
		return;

	recheck = getsid(0);
	if (recheck == (pid_t)-1)
		return;

	if (recheck != got) {
		output(0, "getsid oracle: getsid(0)=%d on syscall return but "
		       "re-read=%d\n", got, recheck);
		__atomic_add_fetch(&shm->stats.getsid_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_getsid = {
	.name = "getsid",
	.group = GROUP_PROCESS,
	.num_args = 1,
	.argtype = { [0] = ARG_PID },
	.argname = { [0] = "pid" },
	.rettype = RET_PID_T,
	.post = post_getsid,
};
