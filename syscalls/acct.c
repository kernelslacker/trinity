/*
 * SYSCALL_DEFINE1(acct, const char __user *, name)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "sanitise.h"

struct syscallentry syscall_acct = {
	.name = "acct",
	.num_args = 1,
	.argtype = { [0] = ARG_PATHNAME },
	.argname = { [0] = "name" },
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
};
