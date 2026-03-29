/*
 * SYSCALL_DEFINE1(times, struct tms __user *, tbuf)
 */
#include "sanitise.h"

struct syscallentry syscall_times = {
	.name = "times",
	.group = GROUP_TIME,
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "tbuf" },
};
