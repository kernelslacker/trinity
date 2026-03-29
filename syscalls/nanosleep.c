/*
 * SYSCALL_DEFINE2(nanosleep, struct timespec __user *, rqtp, struct timespec __user *, rmtp)
 */
#include "sanitise.h"

struct syscallentry syscall_nanosleep = {
	.name = "nanosleep",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS },
	.argname = { [0] = "rqtp", [1] = "rmtp" },
	.flags = AVOID_SYSCALL, // Boring.  Can cause long sleeps.
};
