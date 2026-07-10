/*
 * SYSCALL_DEFINE5(waitid, int, which, pid_t, upid, struct siginfo __user *,
	infop, int, options, struct rusage __user *, ru)
 */
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include "objects.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/wait.h"
static unsigned long waitid_options[] = {
	WNOHANG, WEXITED, WSTOPPED, WCONTINUED, WNOWAIT,
	__WALL, __WCLONE, __WNOTHREAD,
};

static unsigned long waitid_which[] = {
	P_ALL, P_PID, P_PGID, P_PIDFD,
};

/*
 * When which==P_PIDFD, upid (a2) must be a real pidfd, not a pid.
 * Re-resolve a live pidfd from the OBJ_FD_PIDFD pool (mirrors the
 * versioned slot-pick pattern in mq_timedsend / fds/pidfd.c) and plant
 * it into a2. Empty pool -> downgrade to P_ALL, which ignores a2, so
 * we never hand the kernel a random pid dressed up as a fd.
 */
static void arm_pidfd(struct syscallrecord *rec)
{
	struct object *obj;
	int i;

	for (i = 0; i < 16; i++) {
		obj = get_random_object(OBJ_FD_PIDFD, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_PIDFD))
			continue;
		if (obj->pidfdobj.fd < 0)
			continue;
		rec->a2 = (unsigned long) obj->pidfdobj.fd;
		return;
	}

	rec->a1 = P_ALL;
}

static void sanitise_waitid(struct syscallrecord *rec)
{
	if (rec->a1 == P_PIDFD)
		arm_pidfd(rec);

	avoid_shared_buffer_out(&rec->a3, sizeof(siginfo_t));
	avoid_shared_buffer_out(&rec->a5, sizeof(struct rusage));
}

/*
 * Kernel ABI: waitid() is RET_ZERO_SUCCESS — it returns 0 on success
 * (with the reaped child's identity copied into *infop->si_pid, not the
 * retval) and -1 on failure. Structurally distinct from waitpid/wait4,
 * which return the pid in retval. Any retval other than 0 or -1 is a
 * kernel ABI regression. Mirrors the strong-validator pattern from the
 * VAL11/VAL12 series.
 */
static void post_waitid(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == 0 || ret == -1L)
		return;

	output(0, "waitid oracle: retval %ld is invalid (must be 0 on success or -1 on failure)\n",
	       ret);
	post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_waitid = {
	.name = "waitid",
	.group = GROUP_PROCESS,
	.num_args = 5,
	.argtype = { [0] = ARG_OP, [1] = ARG_PID, [2] = ARG_ADDRESS, [3] = ARG_LIST, [4] = ARG_ADDRESS },
	.argname = { [0] = "which", [1] = "upid", [2] = "infop", [3] = "options", [4] = "ru" },
	.arg_params[0].list = ARGLIST(waitid_which),
	.arg_params[3].list = ARGLIST(waitid_options),
	.sanitise = sanitise_waitid,
	.post = post_waitid,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
};
