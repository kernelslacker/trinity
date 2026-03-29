/*
 * SYSCALL_DEFINE1(stime, time_t __user *, tptr)
 */
#include "sanitise.h"

struct syscallentry syscall_stime = {
	.name = "stime",
	.group = GROUP_TIME,
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "tptr" },
};
