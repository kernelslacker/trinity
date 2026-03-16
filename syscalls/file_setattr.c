/*
 * SYSCALL_DEFINE5(file_setattr, int, dfd, const char __user *, filename,
 *		struct file_attr __user *, ufattr, size_t, usize,
 *		unsigned int, at_flags)
 */
#include <fcntl.h>
#include "sanitise.h"
#include "compat.h"

static unsigned long file_setattr_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

struct syscallentry syscall_file_setattr = {
	.name = "file_setattr",
	.num_args = 5,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_PATHNAME,
	.arg3name = "ufattr",
	.arg3type = ARG_ADDRESS,
	.arg4name = "usize",
	.arg4type = ARG_LEN,
	.arg5name = "at_flags",
	.arg5type = ARG_LIST,
	.arg5list = ARGLIST(file_setattr_at_flags),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
