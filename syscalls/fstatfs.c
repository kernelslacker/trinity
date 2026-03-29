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
	.argtype = { [0] = ARG_FD, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "fd", [1] = "buf" },
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
	.argtype = { [0] = ARG_FD, [1] = ARG_LEN, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "fd", [1] = "sz", [2] = "buf" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
