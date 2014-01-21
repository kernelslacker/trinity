/*
 * SYSCALL_DEFINE2(sched_setattr, pid_t, pid, struct sched_attr __user *, uattr)
 */
#include "sanitise.h"

struct syscallentry syscall_sched_setattr = {
	.name = "sched_setattr",
	.num_args = 2,
	.arg1name = "pid",
	.arg1type = ARG_PID,
	.arg2name = "uattr",
	.arg2type = ARG_ADDRESS,
};
