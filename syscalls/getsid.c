/*
 * SYSCALL_DEFINE1(getsid, pid_t, pid)
 */
#include <sys/types.h>
#include <unistd.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

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
