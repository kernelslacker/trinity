/*
 * SYSCALL_DEFINE1(chdir, const char __user *, filename)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "sanitise.h"

struct syscallentry syscall_chdir = {
	.name = "chdir",
	.num_args = 1,
	.argtype = { [0] = ARG_PATHNAME },
	.argname = { [0] = "filename" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
