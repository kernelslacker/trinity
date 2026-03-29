/*
 * SYSCALL_DEFINE2(setpgid, pid_t, pid, pid_t, pgid)
 */
#include "sanitise.h"

struct syscallentry syscall_setpgid = {
	.name = "setpgid",
	.group = GROUP_PROCESS,
	.num_args = 2,
	.argtype = { [0] = ARG_PID, [1] = ARG_PID },
	.argname = { [0] = "pid", [1] = "pgid" },
};
