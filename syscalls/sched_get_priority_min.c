/*
 * SYSCALL_DEFINE1(sched_get_priority_min, int, policy)
 */
#include "sanitise.h"

struct syscallentry syscall_sched_get_priority_min = {
	.name = "sched_get_priority_min",
	.group = GROUP_SCHED,
	.num_args = 1,
	.arg1name = "policy",
};
