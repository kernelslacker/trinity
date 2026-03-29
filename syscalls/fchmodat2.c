/*
 * SYSCALL_DEFINE4(fchmodat2, int, dfd, const char __user *, filename,
 *		umode_t, mode, unsigned int, flags)
 */
#include "sanitise.h"

#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW	0x100
#endif

static unsigned long fchmodat2_flags[] = {
	AT_SYMLINK_NOFOLLOW,
};

struct syscallentry syscall_fchmodat2 = {
	.name = "fchmodat2",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_MODE_T, [3] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "mode", [3] = "flags" },
	.arg4list = ARGLIST(fchmodat2_flags),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
