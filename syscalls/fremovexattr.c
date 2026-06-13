/*
 * SYSCALL_DEFINE2(fremovexattr, int, fd, const char __user *, name)
 */
#include "sanitise.h"

struct syscallentry syscall_fremovexattr = {
	.name = "fremovexattr",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_XATTR_NAME },
	.argname = { [0] = "fd", [1] = "name" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
