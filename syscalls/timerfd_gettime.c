/*
 * SYSCALL_DEFINE2(timerfd_gettime, int, ufd, struct itimerspec __user *, otmr)
 */
#include "sanitise.h"

struct syscallentry syscall_timerfd_gettime = {
	.name = "timerfd_gettime",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_FD_TIMERFD, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "ufd", [1] = "otmr" },
	.flags = NEED_ALARM,
	.rettype = RET_ZERO_SUCCESS,
};
