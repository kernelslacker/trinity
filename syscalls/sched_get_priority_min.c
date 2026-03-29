/*
 * SYSCALL_DEFINE1(sched_get_priority_min, int, policy)
 */
#include <sched.h>
#include "sanitise.h"

static unsigned long sched_policies[] = {
	SCHED_OTHER, SCHED_FIFO, SCHED_RR,
	SCHED_BATCH, SCHED_IDLE, SCHED_DEADLINE,
};

struct syscallentry syscall_sched_get_priority_min = {
	.name = "sched_get_priority_min",
	.group = GROUP_SCHED,
	.num_args = 1,
	.argtype = { [0] = ARG_OP },
	.argname = { [0] = "policy" },
	.arg_params[0].list = ARGLIST(sched_policies),
};
