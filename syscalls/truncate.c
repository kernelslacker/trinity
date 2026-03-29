/*
 * SYSCALL_DEFINE2(truncate, const char __user *, path, long, length)
 */
#include "sanitise.h"

struct syscallentry syscall_truncate = {
	.name = "truncate",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_LEN },
	.argname = { [0] = "path", [1] = "length" },
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE(truncate64)(const char __user * path, loff_t length)
 */

struct syscallentry syscall_truncate64 = {
	.name = "truncate64",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_LEN },
	.argname = { [0] = "path", [1] = "length" },
	.group = GROUP_VFS,
};
