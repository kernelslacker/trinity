/*
 * SYSCALL_DEFINE(fadvise64)(int fd, loff_t offset, size_t len, int advice)
 *
 * On success, zero is returned.
 * On error, an error number is returned.
 */
#include <fcntl.h>
#include "random.h"
#include "sanitise.h"

static void sanitise_fadvise64(struct syscallrecord *rec)
{
	/* Negative offsets produce EINVAL. */
	rec->a2 = rand64() & 0x7fffffff;
}

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
	.argtype = { [0] = ARG_FD, [2] = ARG_LEN, [3] = ARG_OP },
	.argname = { [0] = "fd", [1] = "offset", [2] = "len", [3] = "advice" },
	.arg4list = ARGLIST(fadvise_flags),
	.sanitise = sanitise_fadvise64,
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
	.argtype = { [0] = ARG_FD, [2] = ARG_LEN, [3] = ARG_OP },
	.argname = { [0] = "fd", [1] = "offset", [2] = "len", [3] = "advice" },
	.arg4list = ARGLIST(fadvise_flags),
	.sanitise = sanitise_fadvise64,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

#else

/*
 * asmlinkage long sys_arm_fadvise64_64(int fd, int advice, loff_t offset, loff_t len)
 * ARM has same as fadvise64 but with other argument order.
 */
static void sanitise_arm_fadvise64_64(struct syscallrecord *rec)
{
	/* Negative offsets produce EINVAL. */
	rec->a3 = rand64() & 0x7fffffff;
}

struct syscallentry syscall_arm_fadvise64_64 = {
	.name = "fadvise64_64",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_OP, [3] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "advice", [2] = "offset", [3] = "len" },
	.arg2list = ARGLIST(fadvise_flags),
	.sanitise = sanitise_arm_fadvise64_64,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
#endif
