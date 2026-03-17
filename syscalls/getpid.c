/*
 * SYSCALL_DEFINE0(getpid)
 */
#include "sanitise.h"

struct syscallentry syscall_getpid = {
	.name = "getpid",
	.group = GROUP_PROCESS,
	.num_args = 0,
	.rettype = RET_PID_T,
};
