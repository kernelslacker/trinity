/*
 * SYSCALL_DEFINE5(waitid, int, which, pid_t, upid, struct siginfo __user *,
	infop, int, options, struct rusage __user *, ru)
 */
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include "sanitise.h"

static unsigned long waitid_options[] = {
	WNOHANG, WEXITED, WSTOPPED, WCONTINUED, WNOWAIT,
};

static unsigned long waitid_which[] = {
	P_ALL, P_PID, P_PGID,
};

static void sanitise_waitid(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a3, sizeof(siginfo_t));
	avoid_shared_buffer(&rec->a5, sizeof(struct rusage));
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
};
