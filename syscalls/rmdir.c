/*
 * SYSCALL_DEFINE1(rmdir, const char __user *, pathname)
 */
#include "sanitise.h"

struct syscallentry syscall_rmdir = {
	.name =  "rmdir",
	.num_args = 1,
	.argtype = { [0] = ARG_PATHNAME },
	.argname = { [0] = "pathname" },
	.group = GROUP_VFS,
};
