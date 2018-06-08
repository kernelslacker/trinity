/*
 * SYSCALL_DEFINE2(symlink, const char __user *, oldname, const char __user *, newname)
 */
#include "sanitise.h"

struct syscallentry syscall_symlink = {
	.name = "symlink",
	.num_args = 2,
	.arg1name = "oldname",
	.arg1type = ARG_PATHNAME,
	.arg2name = "newname",
	.arg2type = ARG_PATHNAME,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE3(symlinkat, const char __user *, oldname,
	 int, newdfd, const char __user *, newname)
 */

struct syscallentry syscall_symlinkat = {
	.name = "symlinkat",
	.num_args = 3,
	.arg1name = "oldname",
	.arg1type = ARG_PATHNAME,
	.arg2name = "newdfd",
	.arg2type = ARG_FD,
	.arg3name = "newname",
	.arg3type = ARG_PATHNAME,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
