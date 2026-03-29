/*
 * SYSCALL_DEFINE3(fchown, unsigned int, fd, uid_t, user, gid_t, group)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <fcntl.h>
#include "sanitise.h"

struct syscallentry syscall_fchown = {
	.name = "fchown",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "fd", [1] = "user", [2] = "group" },
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 65535,
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 65535,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE3(fchown16, unsigned int, fd, old_uid_t, user, old_gid_t, group)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */

struct syscallentry syscall_fchown16 = {
	.name = "fchown16",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "fd", [1] = "user", [2] = "group" },
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 65535,
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 65535,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE5(fchownat, int, dfd, const char __user *, filename, uid_t, user,
	gid_t, group, int, flag)
 *
 * On success, fchownat() returns 0.
 *  On error, -1 is returned and errno is set to indicate the error.
 */

static unsigned long fchownat_flags[] = {
	AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW,
};

struct syscallentry syscall_fchownat = {
	.name = "fchownat",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_RANGE, [3] = ARG_RANGE, [4] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "user", [3] = "group", [4] = "flag" },
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 65535,
	.arg_params[3].range.low = 0,
	.arg_params[3].range.hi = 65535,
	.arg_params[4].list = ARGLIST(fchownat_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
