/*
 * SYSCALL_DEFINE2(fstat64, unsigned long, fd, struct stat64 __user *, statbuf)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <fcntl.h>
#include "sanitise.h"

struct syscallentry syscall_fstat64 = {
	.name = "fstat64",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "fd", [1] = "statbuf" },
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

static unsigned long fstatat_flags[] = {
	AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW, AT_NO_AUTOMOUNT,
};

struct syscallentry syscall_fstatat64 = {
	.name = "fstatat64",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_NON_NULL_ADDRESS, [3] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "statbuf", [3] = "flag" },
	.arg4list = ARGLIST(fstatat_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
