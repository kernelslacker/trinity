/*
 * SYSCALL_DEFINE2(pivot_root, const char __user *, new_root, const char __user *, put_old)
 */
#include "sanitise.h"

struct syscallentry syscall_pivot_root = {
	.name = "pivot_root",
	.num_args = 2,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS },
	.argname = { [0] = "new_root", [1] = "put_old" },
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
};
