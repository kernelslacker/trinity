/*
 * SYSCALL_DEFINE4(sendfile, int, out_fd, int, in_fd, off_t __user *, offset, size_t, count)
 */
#include "sanitise.h"

struct syscallentry syscall_sendfile = {
	.name = "sendfile",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_FD, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "out_fd", [1] = "in_fd", [2] = "offset", [3] = "count" },
	.flags = NEED_ALARM | IGNORE_ENOSYS,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE4(sendfile64, int, out_fd, int, in_fd, loff_t __user *, offset, size_t, count)
 */

struct syscallentry syscall_sendfile64 = {
	.name = "sendfile64",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_FD, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "out_fd", [1] = "in_fd", [2] = "offset", [3] = "count" },
	.flags = NEED_ALARM | IGNORE_ENOSYS,
	.group = GROUP_VFS,
};
