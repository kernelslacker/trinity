/*
 * SYSCALL_DEFINE1(sched_getscheduler, pid_t, pid)
 */
#include "sanitise.h"

struct syscallentry syscall_sched_getscheduler = {
	.name = "sched_getscheduler",
	.group = GROUP_SCHED,
	.num_args = 1,
	.argtype = { [0] = ARG_PID },
	.argname = { [0] = "pid" },
	.rettype = RET_ZERO_SUCCESS,
};
