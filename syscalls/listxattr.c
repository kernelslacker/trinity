#include "sanitise.h"

/*
 * SYSCALL_DEFINE3(flistxattr, int, fd, char __user *, list, size_t, size)
 */
struct syscallentry syscall_flistxattr = {
	.name = "flistxattr",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "list", [2] = "size" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE3(listxattr, const char __user *, pathname, char __user *, list, size_t, size
 */
struct syscallentry syscall_listxattr = {
	.name = "listxattr",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "pathname", [1] = "list", [2] = "size" },
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE3(llistxattr, const char __user *, pathname, char __user *, list, size_t, size)
 */
struct syscallentry syscall_llistxattr = {
	.name = "llistxattr",
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "pathname", [1] = "list", [2] = "size" },
	.num_args = 3,
	.group = GROUP_VFS,
};
