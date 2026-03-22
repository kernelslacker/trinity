/*
 * SYSCALL_DEFINE2(timer_gettime, timer_t, timer_id, struct itimerspec __user *, setting)
 */
#include "sanitise.h"

struct syscallentry syscall_timer_gettime = {
	.name = "timer_gettime",
	.group = GROUP_TIME,
	.num_args = 2,
	.arg1name = "timer_id",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = 31,
	.arg2name = "setting",
	.arg2type = ARG_ADDRESS,
};
