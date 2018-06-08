/*
 * SYSCALL_DEFINE(fadvise64)(int fd, loff_t offset, size_t len, int advice)
 *
 * On success, zero is returned.
 * On error, an error number is returned.
 */
#include <fcntl.h>
#include "sanitise.h"

static unsigned long fadvise_flags[] = {
	POSIX_FADV_NORMAL,
	POSIX_FADV_SEQUENTIAL,
	POSIX_FADV_RANDOM,
	POSIX_FADV_NOREUSE,
	POSIX_FADV_WILLNEED,
	POSIX_FADV_DONTNEED,
};

struct syscallentry syscall_fadvise64 = {
	.name = "fadvise64",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "offset",
	.arg3name = "len",
	.arg3type = ARG_LEN,
	.arg4name = "advice",
	.arg4type = ARG_OP,
	.arg4list = ARGLIST(fadvise_flags),
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
	.arg4type = ARG_OP,
	.arg4list = ARGLIST(fadvise_flags),
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
	.arg2type = ARG_OP,
	.arg2list = ARGLIST(fadvise_flags),
	.arg3name = "offset",
	.arg4name = "len",
	.arg4type = ARG_LEN,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
#endif
