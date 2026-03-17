/*
 * SYSCALL_DEFINE0(getppid)
 */
#include "sanitise.h"

struct syscallentry syscall_getppid = {
	.name = "getppid",
	.group = GROUP_PROCESS,
	.num_args = 0,
	.rettype = RET_PID_T,
};
