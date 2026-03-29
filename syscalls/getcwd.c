/*
 * SYSCALL_DEFINE2(getcwd, char __user *, buf, unsigned long, size)
 */
#include "sanitise.h"

struct syscallentry syscall_getcwd = {
	.name = "getcwd",
	.num_args = 2,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_LEN },
	.argname = { [0] = "buf", [1] = "size" },
	.rettype = RET_PATH,
	.group = GROUP_VFS,
};
