/*
 * SYSCALL_DEFINE1(unlink, const char __user *, pathname)
 */
#include <fcntl.h>
#include "sanitise.h"

struct syscallentry syscall_unlink = {
	.name = "unlink",
	.num_args = 1,
	.argtype = { [0] = ARG_PATHNAME },
	.argname = { [0] = "pathname" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE3(unlinkat, int, dfd, const char __user *, pathname, int, flag)
 */

static unsigned long unlinkat_flags[] = {
	0, AT_REMOVEDIR,
};

struct syscallentry syscall_unlinkat = {
	.name = "unlinkat",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "pathname", [2] = "flag" },
	.arg_params[2].list = ARGLIST(unlinkat_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
