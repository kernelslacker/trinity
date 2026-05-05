/*
 * SYSCALL_DEFINE2(symlink, const char __user *, oldname, const char __user *, newname)
 */
#include "sanitise.h"

struct syscallentry syscall_symlink = {
	.name = "symlink",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_PATHNAME },
	.argname = { [0] = "oldname", [1] = "newname" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE3(symlinkat, const char __user *, oldname,
	 int, newdfd, const char __user *, newname)
 */

struct syscallentry syscall_symlinkat = {
	.name = "symlinkat",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_FD, [2] = ARG_PATHNAME },
	.argname = { [0] = "oldname", [1] = "newdfd", [2] = "newname" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
