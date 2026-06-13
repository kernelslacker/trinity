/*
 * SYSCALL_DEFINE4(removexattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, const char __user *, name)
 */
#include "sanitise.h"
#include "xattr.h"
#include "compat.h"

struct syscallentry syscall_removexattrat = {
	.name = "removexattrat",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [3] = ARG_XATTR_NAME },
	.argname = { [0] = "dfd", [1] = "pathname", [2] = "at_flags", [3] = "name" },
	.arg_params[2].list = ARGLIST(xattrat_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
