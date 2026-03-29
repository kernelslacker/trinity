/*
 * SYSCALL_DEFINE2(timer_gettime, timer_t, timer_id, struct itimerspec __user *, setting)
 */
#include "sanitise.h"

struct syscallentry syscall_timer_gettime = {
	.name = "timer_gettime",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "timer_id", [1] = "setting" },
	.low1range = 0,
	.hi1range = 31,
};
