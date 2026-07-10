/*
 * SYSCALL_DEFINE2(mkdir, const char __user *, pathname, int, mode)
 */
#include "sanitise.h"

struct syscallentry syscall_mkdir = {
	.name = "mkdir",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_MODE_T },
	.argname = { [0] = "pathname", [1] = "mode" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE3(mkdirat, int, dfd, const char __user *, pathname, int, mode)
 */
#include "sanitise.h"

struct syscallentry syscall_mkdirat = {
	.name = "mkdirat",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_MODE_T },
	.argname = { [0] = "dfd", [1] = "pathname", [2] = "mode" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
