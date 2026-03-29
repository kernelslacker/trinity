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
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_ADDRESS, [3] = ARG_LEN, [4] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "ufattr", [3] = "usize", [4] = "at_flags" },
	.arg5list = ARGLIST(file_setattr_at_flags),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
