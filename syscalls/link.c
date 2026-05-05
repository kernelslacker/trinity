/*
 * SYSCALL_DEFINE2(link, const char __user *, oldname, const char __user *, newname)
 */
#include "sanitise.h"

struct syscallentry syscall_link = {
	.name = "link",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_PATHNAME },
	.argname = { [0] = "oldname", [1] = "newname" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
