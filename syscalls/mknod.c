/*
 * SYSCALL_DEFINE3(mknod, const char __user *, filename, int, mode, unsigned, dev)
 */
#include "sanitise.h"

struct syscallentry syscall_mknod = {
	.name = "mknod",
	.num_args = 3,
	.arg1name = "filename",
	.arg1type = ARG_PATHNAME,
	.arg2name = "mode",
	.arg2type = ARG_MODE_T,
	.arg3name = "dev",
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE4(mknodat, int, dfd, const char __user *, filename, int, mode, unsigned, dev)
 */

struct syscallentry syscall_mknodat = {
	.name = "mknodat",
	.num_args = 4,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_PATHNAME,
	.arg3name = "mode",
	.arg4name = "dev",
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
