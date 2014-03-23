/*
 * SYSCALL_DEFINE(fadvise64)(int fd, loff_t offset, size_t len, int advice)
 *
 * On success, zero is returned.
 * On error, an error number is returned.
 */
#include "sanitise.h"

struct syscallentry syscall_fadvise64 = {
	.name = "fadvise64",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "offset",
	.arg3name = "len",
	.arg3type = ARG_LEN,
	.arg4name = "advice",
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

#ifndef __arm__
/*
 * SYSCALL_DEFINE(fadvise64_64)(int fd, loff_t offset, loff_t len, int advice)
 *
 * On success, zero is returned.
 * On error, an error number is returned.
 */

struct syscallentry syscall_fadvise64_64 = {
	.name = "fadvise64_64",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "offset",
	.arg3name = "len",
	.arg3type = ARG_LEN,
	.arg4name = "advice",
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

#else

/*
 * asmlinkage long sys_arm_fadvise64_64(int fd, int advice, loff_t offset, loff_t len)
 * ARM has same as fadvise64 but with other argument order.
 */
struct syscallentry syscall_arm_fadvise64_64 = {
	.name = "fadvise64_64",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "advice",
	.arg3name = "offset",
	.arg4name = "len",
	.arg4type = ARG_LEN,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
#endif
