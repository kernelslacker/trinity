/*
 * SYSCALL_DEFINE2(fstatfs, unsigned int, fd, struct statfs __user *, buf)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "sanitise.h"

struct syscallentry syscall_fstatfs = {
	.name = "fstatfs",
	.num_args = 2,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "buf",
	.arg2type = ARG_ADDRESS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE3(fstatfs64, unsigned int, fd, size_t, sz, struct statfs64 __user *, buf)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */

struct syscallentry syscall_fstatfs64 = {
	.name = "fstatfs64",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "sz",
	.arg3name = "buf",
	.arg3type = ARG_ADDRESS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
