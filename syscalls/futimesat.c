/*
 * SYSCALL_DEFINE3(futimesat, int, dfd, const char __user *, filename,
	 struct timeval __user *, utimes)
 */
#include "sanitise.h"

struct syscallentry syscall_futimesat = {
	.name = "futimesat",
	.group = GROUP_TIME,
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_ADDRESS },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "utimes" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
};
