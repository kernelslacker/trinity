/*
 * SYSCALL_DEFINE3(readlink, const char __user *, path, char __user *, buf, int, bufsiz)
 */
#include "sanitise.h"

struct syscallentry syscall_readlink = {
	.name = "readlink",
	.num_args = 3,
	.arg1name = "path",
	.arg1type = ARG_PATHNAME,
	.arg2name = "buf",
	.arg2type = ARG_ADDRESS,
	.arg3name = "bufsiz",
	.arg3type = ARG_LEN,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE4(readlinkat, int, dfd, const char __user *, pathname,
	 char __user *, buf, int, bufsiz)
 */

struct syscallentry syscall_readlinkat = {
	.name = "readlinkat",
	.num_args = 4,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "pathname",
	.arg2type = ARG_PATHNAME,
	.arg3name = "buf",
	.arg3type = ARG_ADDRESS,
	.arg4name = "bufsiz",
	.arg4type = ARG_LEN,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
