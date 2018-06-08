/*
 * SYSCALL_DEFINE0(sched_yield)
 */
#include "sanitise.h"

struct syscallentry syscall_sched_yield = {
	.name = "sched_yield",
	.num_args = 0,
};
