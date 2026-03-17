/*
 * SYSCALL_DEFINE1(getsid, pid_t, pid)
 */
#include "sanitise.h"

struct syscallentry syscall_getsid = {
	.name = "getsid",
	.group = GROUP_PROCESS,
	.num_args = 1,
	.arg1name = "pid",
	.arg1type = ARG_PID,
};
