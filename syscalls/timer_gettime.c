/*
 * SYSCALL_DEFINE2(timer_gettime, timer_t, timer_id, struct itimerspec __user *, setting)
 */
#include <time.h>
#include "sanitise.h"

static void sanitise_timer_gettime(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, sizeof(struct itimerspec));
}

struct syscallentry syscall_timer_gettime = {
	.name = "timer_gettime",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "timer_id", [1] = "setting" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 31,
	.sanitise = sanitise_timer_gettime,
	.rettype = RET_ZERO_SUCCESS,
};
