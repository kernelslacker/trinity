/*
 * SYSCALL_DEFINE1(nice, int, increment)
 */
#include "sanitise.h"

struct syscallentry syscall_nice = {
	.name = "nice",
	.num_args = 1,
	.arg1name = "increment",
	.arg1type = ARG_RANGE,
	.low1range = -20,
	.hi1range = 19,
	.group = GROUP_SCHED,
};
