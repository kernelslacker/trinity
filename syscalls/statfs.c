/*
 * SYSCALL_DEFINE2(statfs, const char __user *, pathname, struct statfs __user *, buf)
 */
#include "sanitise.h"

struct syscallentry syscall_statfs = {
	.name = "statfs",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "pathname", [1] = "buf" },
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE3(statfs64, const char __user *, pathname, size_t, sz, struct statfs64 __user *, buf)
 */

struct syscallentry syscall_statfs64 = {
	.name = "statfs64",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_LEN, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "pathname", [1] = "sz", [2] = "buf" },
	.group = GROUP_VFS,
};
