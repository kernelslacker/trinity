/*
 * SYSCALL_DEFINE3(sched_setscheduler, pid_t, pid, int, policy, struct sched_param __user *, param)
 */
#include <sched.h>
#include "compat.h"
#include "sanitise.h"

static unsigned long sched_setscheduler_policies[] = {
	SCHED_OTHER, SCHED_FIFO, SCHED_RR, SCHED_BATCH,
	SCHED_IDLE, SCHED_DEADLINE,
};

struct syscallentry syscall_sched_setscheduler = {
	.name = "sched_setscheduler",
	.group = GROUP_SCHED,
	.num_args = 3,
	.argtype = { [0] = ARG_PID, [1] = ARG_OP, [2] = ARG_ADDRESS },
	.argname = { [0] = "pid", [1] = "policy", [2] = "param" },
	.arg2list = ARGLIST(sched_setscheduler_policies),
};
