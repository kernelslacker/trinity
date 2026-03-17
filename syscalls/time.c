/*
 * SYSCALL_DEFINE1(time, time_t __user *, tloc)
 */
#include "sanitise.h"

struct syscallentry syscall_time = {
	.name = "time",
	.group = GROUP_TIME,
	.num_args = 1,
	.arg1name = "tloc",
	.arg1type = ARG_ADDRESS,
};
