/*
 * SYSCALL_DEFINE2(utimes, char __user *, filename, struct timeval __user *, utimes)
 */
#include "sanitise.h"

struct syscallentry syscall_utimes = {
	.name = "utimes",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_ADDRESS },
	.argname = { [0] = "filename", [1] = "utimes" },
};
