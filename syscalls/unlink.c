/*
 * SYSCALL_DEFINE1(unlink, const char __user *, pathname)
 */
#include "sanitise.h"

struct syscallentry syscall_unlink = {
	.name = "unlink",
	.num_args = 1,
	.arg1name = "pathname",
	.arg1type = ARG_PATHNAME,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE3(unlinkat, int, dfd, const char __user *, pathname, int, flag)
 */

struct syscallentry syscall_unlinkat = {
	.name = "unlinkat",
	.num_args = 3,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "pathname",
	.arg2type = ARG_PATHNAME,
	.arg3name = "flag",
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
