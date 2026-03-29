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
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 31,
};
