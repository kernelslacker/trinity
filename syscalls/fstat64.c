/*
 * SYSCALL_DEFINE2(fstat64, unsigned long, fd, struct stat64 __user *, statbuf)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "sanitise.h"

struct syscallentry syscall_fstat64 = {
	.name = "fstat64",
	.num_args = 2,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "statbuf",
	.arg2type = ARG_ADDRESS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,
	struct stat64 __user *, statbuf, int, flag)
 *
 * On success, fstatat() returns 0.
 * On error, -1 is returned and errno is set to indicate the error.
 */

struct syscallentry syscall_fstatat64 = {
	.name = "fstatat64",
	.num_args = 4,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_PATHNAME,
	.arg3name = "statbuf",
	.arg3type = ARG_ADDRESS,
	.arg4name = "flag",
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
