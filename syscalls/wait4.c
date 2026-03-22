/*
 * SYSCALL_DEFINE4(wait4, pid_t, upid, int __user *, stat_addr,
	 int, options, struct rusage __user *, ru)
 */
#include <sys/wait.h>
#include "sanitise.h"

static unsigned long wait_options[] = {
	WNOHANG, WUNTRACED, WCONTINUED,
};

struct syscallentry syscall_wait4 = {
	.name = "wait4",
	.group = GROUP_PROCESS,
	.num_args = 4,
	.arg1name = "upid",
	.arg1type = ARG_PID,
	.arg2name = "stat_addr",
	.arg2type = ARG_ADDRESS,
	.arg3name = "options",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(wait_options),
	.arg4name = "ru",
	.arg4type = ARG_ADDRESS,
};
