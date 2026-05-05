/*
 * SYSCALL_DEFINE3(mknod, const char __user *, filename, int, mode, unsigned, dev)
 */
#include "sanitise.h"

struct syscallentry syscall_mknod = {
	.name = "mknod",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_MODE_T },
	.argname = { [0] = "filename", [1] = "mode", [2] = "dev" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE4(mknodat, int, dfd, const char __user *, filename, int, mode, unsigned, dev)
 */

struct syscallentry syscall_mknodat = {
	.name = "mknodat",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_MODE_T },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "mode", [3] = "dev" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM | NEEDS_ROOT,
	.group = GROUP_VFS,
};
