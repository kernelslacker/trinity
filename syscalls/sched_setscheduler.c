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
	.num_args = 3,
	.arg1name = "pid",
	.arg1type = ARG_PID,
	.arg2name = "policy",
	.arg2type = ARG_OP,
	.arg2list = ARGLIST(sched_setscheduler_policies),
	.arg3name = "param",
	.arg3type = ARG_ADDRESS,
};
