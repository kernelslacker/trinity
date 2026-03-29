/*
 * SYSCALL_DEFINE2(sched_getparam, pid_t, pid, struct sched_param __user *, param)
 */
#include "sanitise.h"

struct syscallentry syscall_sched_getparam = {
	.name = "sched_getparam",
	.group = GROUP_SCHED,
	.num_args = 2,
	.argtype = { [0] = ARG_PID, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "pid", [1] = "param" },
};
