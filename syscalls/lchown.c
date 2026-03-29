/*
 * SYSCALL_DEFINE3(lchown, const char __user *, filename, uid_t, user, gid_t, group)
 */
#include "sanitise.h"

struct syscallentry syscall_lchown = {
	.name = "lchown",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "filename", [1] = "user", [2] = "group" },
	.low2range = 0,
	.hi2range = 65535,
	.low3range = 0,
	.hi3range = 65535,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE3(lchown16, const char __user *, filename, old_uid_t, user, old_gid_t, group)
 */

struct syscallentry syscall_lchown16 = {
	.name = "lchown16",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "filename", [1] = "user", [2] = "group" },
	.low2range = 0,
	.hi2range = 65535,
	.low3range = 0,
	.hi3range = 65535,
	.group = GROUP_VFS,
};
