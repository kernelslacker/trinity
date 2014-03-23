/*
 * SYSCALL_DEFINE2(ftruncate, unsigned int, fd, unsigned long, length)
 */
#include "sanitise.h"

struct syscallentry syscall_ftruncate = {
	.name = "ftruncate",
	.num_args = 2,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "length",
	.arg2type = ARG_LEN,
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
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "length",
	.arg2type = ARG_LEN,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
