/*
 * SYSCALL_DEFINE6(getxattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, const char __user *, name,
 *		struct xattr_args __user *, uargs, size_t, usize)
 */
#include <fcntl.h>
#include "sanitise.h"
#include "compat.h"

static unsigned long getxattrat_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

struct syscallentry syscall_getxattrat = {
	.name = "getxattrat",
	.num_args = 6,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "pathname",
	.arg2type = ARG_PATHNAME,
	.arg3name = "at_flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(getxattrat_at_flags),
	.arg4name = "name",
	.arg4type = ARG_ADDRESS,
	.arg5name = "uargs",
	.arg5type = ARG_ADDRESS,
	.arg6name = "usize",
	.arg6type = ARG_LEN,
	.group = GROUP_VFS,
};
