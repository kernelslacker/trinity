/*
 * SYSCALL_DEFINE1(unlink, const char __user *, pathname)
 */
#include <fcntl.h>
#include "sanitise.h"

struct syscallentry syscall_unlink = {
	.name = "unlink",
	.num_args = 1,
	.arg1name = "pathname",
	.arg1type = ARG_PATHNAME,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE3(unlinkat, int, dfd, const char __user *, pathname, int, flag)
 */

static unsigned long unlinkat_flags[] = {
	0, AT_REMOVEDIR,
};

struct syscallentry syscall_unlinkat = {
	.name = "unlinkat",
	.num_args = 3,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "pathname",
	.arg2type = ARG_PATHNAME,
	.arg3name = "flag",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(unlinkat_flags),
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
