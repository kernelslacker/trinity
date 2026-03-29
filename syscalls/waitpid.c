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
	.argtype = { [0] = ARG_PID, [1] = ARG_ADDRESS, [2] = ARG_LIST },
	.argname = { [0] = "pid", [1] = "stat_addr", [2] = "options" },
	.arg3list = ARGLIST(wait_options),
};
