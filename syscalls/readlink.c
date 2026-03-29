/*
 * SYSCALL_DEFINE3(readlink, const char __user *, path, char __user *, buf, int, bufsiz)
 */
#include "sanitise.h"

struct syscallentry syscall_readlink = {
	.name = "readlink",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "path", [1] = "buf", [2] = "bufsiz" },
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE4(readlinkat, int, dfd, const char __user *, pathname,
	 char __user *, buf, int, bufsiz)
 */

struct syscallentry syscall_readlinkat = {
	.name = "readlinkat",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_NON_NULL_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "dfd", [1] = "pathname", [2] = "buf", [3] = "bufsiz" },
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
