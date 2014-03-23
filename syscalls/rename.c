/*
 * SYSCALL_DEFINE2(rename, const char __user *, oldname, const char __user *, newname
 */
#include "sanitise.h"

struct syscallentry syscall_rename = {
	.name = "rename",
	.num_args = 2,
	.arg1name = "oldname",
	.arg1type = ARG_ADDRESS,
	.arg2name = "newname",
	.arg2type = ARG_ADDRESS,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE4(renameat, int, olddfd, const char __user *, oldname,
	 int, newdfd, const char __user *, newname)
 */

struct syscallentry syscall_renameat = {
	.name = "renameat",
	.num_args = 4,
	.arg1name = "olddfd",
	.arg1type = ARG_FD,
	.arg2name = "oldname",
	.arg2type = ARG_ADDRESS,
	.arg3name = "newdfd",
	.arg3type = ARG_FD,
	.arg4name = "newname",
	.arg4type = ARG_ADDRESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
