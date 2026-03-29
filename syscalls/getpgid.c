/*
 * SYSCALL_DEFINE1(getpgid, pid_t, pid)
 */
#include "sanitise.h"

struct syscallentry syscall_getpgid = {
	.name = "getpgid",
	.group = GROUP_PROCESS,
	.num_args = 1,
	.argtype = { [0] = ARG_PID },
	.argname = { [0] = "pid" },
	.rettype = RET_PID_T,
};
