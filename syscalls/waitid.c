/*
 * SYSCALL_DEFINE5(waitid, int, which, pid_t, upid, struct siginfo __user *,
	infop, int, options, struct rusage __user *, ru)
 */
#include <sys/wait.h>
#include "sanitise.h"

static unsigned long waitid_options[] = {
	WNOHANG, WEXITED, WSTOPPED, WCONTINUED, WNOWAIT,
};

static unsigned long waitid_which[] = {
	P_ALL, P_PID, P_PGID,
};

struct syscallentry syscall_waitid = {
	.name = "waitid",
	.group = GROUP_PROCESS,
	.num_args = 5,
	.arg1name = "which",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(waitid_which),
	.arg2name = "upid",
	.arg2type = ARG_PID,
	.arg3name = "infop",
	.arg3type = ARG_ADDRESS,
	.arg4name = "options",
	.arg4type = ARG_LIST,
	.arg4list = ARGLIST(waitid_options),
	.arg5name = "ru",
	.arg5type = ARG_ADDRESS,
};
