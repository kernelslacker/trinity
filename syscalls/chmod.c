/*
 * SYSCALL_DEFINE2(chmod, const char __user *, filename, mode_t, mode)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "sanitise.h"

struct syscallentry syscall_chmod = {
	.name = "chmod",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_MODE_T },
	.argname = { [0] = "filename", [1] = "mode" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
