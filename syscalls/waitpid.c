/*
 * SYSCALL_DEFINE3(waitpid, pid_t, pid, int __user *, stat_addr, int, options)
 */
#include <sys/wait.h>
#include "sanitise.h"

static unsigned long wait_options[] = {
	WNOHANG, WUNTRACED, WCONTINUED,
};

struct syscallentry syscall_waitpid = {
	.name = "waitpid",
	.group = GROUP_PROCESS,
	.num_args = 3,
	.arg1name = "pid",
	.arg1type = ARG_PID,
	.arg2name = "stat_addr",
	.arg2type = ARG_ADDRESS,
	.arg3name = "options",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(wait_options),
};
