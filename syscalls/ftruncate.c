/*
 * SYSCALL_DEFINE2(ftruncate, unsigned int, fd, unsigned long, length)
 */
#include "sanitise.h"

struct syscallentry syscall_ftruncate = {
	.name = "ftruncate",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "length" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE(ftruncate64)(unsigned int fd, loff_t length)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */

struct syscallentry syscall_ftruncate64 = {
	.name = "ftruncate64",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "length" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
