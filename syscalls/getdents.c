/*
 * SYSCALL_DEFINE3(getdents, unsigned int, fd,
    struct linux_dirent __user *, dirent, unsigned int, count)
 */
#include "sanitise.h"

struct syscallentry syscall_getdents = {
	.name = "getdents",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "dirent", [2] = "count" },
	.rettype = RET_NUM_BYTES,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE3(getdents64, unsigned int, fd,
	 struct linux_dirent64 __user *, dirent, unsigned int, count)
 */

struct syscallentry syscall_getdents64 = {
	.name = "getdents64",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "dirent", [2] = "count" },
	.rettype = RET_NUM_BYTES,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
