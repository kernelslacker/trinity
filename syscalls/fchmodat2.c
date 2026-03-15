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
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_PATHNAME,
	.arg3name = "mode",
	.arg3type = ARG_MODE_T,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = ARGLIST(fchmodat2_flags),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
