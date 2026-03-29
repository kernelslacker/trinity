/*
 * SYSCALL_DEFINE1(timer_getoverrun, timer_t, timer_id)
 */
#include "sanitise.h"

struct syscallentry syscall_timer_getoverrun = {
	.name = "timer_getoverrun",
	.group = GROUP_TIME,
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "timer_id" },
	.low1range = 0,
	.hi1range = 31,
};
