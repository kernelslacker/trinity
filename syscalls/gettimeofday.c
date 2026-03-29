/*
 * SYSCALL_DEFINE2(gettimeofday, struct timeval __user *, tv, struct timezone __user *, tz)
 */
#include "sanitise.h"

struct syscallentry syscall_gettimeofday = {
	.name = "gettimeofday",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS },
	.argname = { [0] = "tv", [1] = "tz" },
};
