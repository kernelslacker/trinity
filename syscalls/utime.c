/*
 * SYSCALL_DEFINE2(utime, char __user *, filename, struct utimbuf __user *, times)
 */
#include "sanitise.h"

struct syscallentry syscall_utime = {
	.name = "utime",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_ADDRESS },
	.argname = { [0] = "filename", [1] = "times" },
};
