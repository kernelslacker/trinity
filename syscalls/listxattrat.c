/*
 * SYSCALL_DEFINE5(listxattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, char __user *, list, size_t, size)
 */
#include <fcntl.h>
#include "sanitise.h"
#include "compat.h"

static unsigned long listxattrat_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

struct syscallentry syscall_listxattrat = {
	.name = "listxattrat",
	.num_args = 5,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "pathname",
	.arg2type = ARG_PATHNAME,
	.arg3name = "at_flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(listxattrat_at_flags),
	.arg4name = "list",
	.arg4type = ARG_ADDRESS,
	.arg5name = "size",
	.arg5type = ARG_LEN,
	.group = GROUP_VFS,
};
