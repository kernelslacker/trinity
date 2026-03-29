/*
 * SYSCALL_DEFINE2(fchmod, unsigned int, fd, mode_t, mode)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "sanitise.h"

struct syscallentry syscall_fchmod = {
	.name = "fchmod",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_MODE_T },
	.argname = { [0] = "fd", [1] = "mode" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE3(fchmodat, int, dfd, const char __user *, filename, mode_t, mode)
 *
 * On success, fchmodat() returns 0.
 * On error, -1 is returned and errno is set to indicate the error.
 */

struct syscallentry syscall_fchmodat = {
	.name = "fchmodat",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_MODE_T },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "mode" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
