/*
 * SYSCALL_DEFINE4(removexattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, const char __user *, name)
 */
#include <fcntl.h>
#include "sanitise.h"
#include "compat.h"

static unsigned long removexattrat_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

struct syscallentry syscall_removexattrat = {
	.name = "removexattrat",
	.num_args = 4,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "pathname",
	.arg2type = ARG_PATHNAME,
	.arg3name = "at_flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(removexattrat_at_flags),
	.arg4name = "name",
	.arg4type = ARG_ADDRESS,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
