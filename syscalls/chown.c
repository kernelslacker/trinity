/*
 * SYSCALL_DEFINE3(chown, const char __user *, filename, uid_t, user, gid_t, group)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "sanitise.h"

struct syscallentry syscall_chown = {
	.name = "chown",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "filename", [1] = "user", [2] = "group" },
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 65535,
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 65535,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE3(chown16, const char __user *, filename, old_uid_t, user, old_gid_t, group)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */

struct syscallentry syscall_chown16 = {
	.name = "chown",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "filename", [1] = "user", [2] = "group" },
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 65535,
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 65535,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
