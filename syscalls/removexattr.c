/*
 * SYSCALL_DEFINE2(removexattr, const char __user *, pathname, const char __user *, name)
 */
#include "sanitise.h"

struct syscallentry syscall_removexattr = {
	.name = "removexattr",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_XATTR_NAME },
	.argname = { [0] = "pathname", [1] = "name" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_XATTR,
};
