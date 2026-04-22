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

static void sanitise_file_getattr(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a3, rec->a4);
}

struct syscallentry syscall_file_getattr = {
	.name = "file_getattr",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_NON_NULL_ADDRESS, [3] = ARG_LEN, [4] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "ufattr", [3] = "usize", [4] = "at_flags" },
	.arg_params[4].list = ARGLIST(file_getattr_at_flags),
	.sanitise = sanitise_file_getattr,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
