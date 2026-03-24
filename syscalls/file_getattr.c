/*
 * SYSCALL_DEFINE5(file_getattr, int, dfd, const char __user *, filename,
 *		struct file_attr __user *, ufattr, size_t, usize,
 *		unsigned int, at_flags)
 */
#include <fcntl.h>
#include "sanitise.h"
#include "compat.h"

static unsigned long file_getattr_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

struct syscallentry syscall_file_getattr = {
	.name = "file_getattr",
	.num_args = 5,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_PATHNAME,
	.arg3name = "ufattr",
	.arg3type = ARG_NON_NULL_ADDRESS,
	.arg4name = "usize",
	.arg4type = ARG_LEN,
	.arg5name = "at_flags",
	.arg5type = ARG_LIST,
	.arg5list = ARGLIST(file_getattr_at_flags),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
