/*
 * SYSCALL_DEFINE6(setxattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, const char __user *, name,
 *		const struct xattr_args __user *, uargs, size_t, usize)
 */
#include <fcntl.h>
#include "sanitise.h"
#include "compat.h"

static unsigned long setxattrat_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

struct syscallentry syscall_setxattrat = {
	.name = "setxattrat",
	.num_args = 6,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "pathname",
	.arg2type = ARG_PATHNAME,
	.arg3name = "at_flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(setxattrat_at_flags),
	.arg4name = "name",
	.arg4type = ARG_ADDRESS,
	.arg5name = "uargs",
	.arg5type = ARG_ADDRESS,
	.arg6name = "usize",
	.arg6type = ARG_LEN,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
