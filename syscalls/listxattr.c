#include "sanitise.h"

/*
 * SYSCALL_DEFINE3(flistxattr, int, fd, char __user *, list, size_t, size)
 */
struct syscallentry syscall_flistxattr = {
	.name = "flistxattr",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "list",
	.arg2type = ARG_ADDRESS,
	.arg3name = "size",
	.arg3type = ARG_LEN,
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
	.arg1name = "pathname",
	.arg1type = ARG_PATHNAME,
	.arg2name = "list",
	.arg2type = ARG_ADDRESS,
	.arg3name = "size",
	.arg3type = ARG_LEN,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE3(llistxattr, const char __user *, pathname, char __user *, list, size_t, size)
 */
struct syscallentry syscall_llistxattr = {
	.name = "llistxattr",
	.arg1name = "pathname",
	.arg1type = ARG_PATHNAME,
	.arg2name = "list",
	.arg2type = ARG_ADDRESS,
	.arg3name = "size",
	.arg3type = ARG_LEN,
	.num_args = 3,
	.group = GROUP_VFS,
};
