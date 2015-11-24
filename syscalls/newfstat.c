/*
 * SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)
 */
#include "sanitise.h"

struct syscallentry syscall_newfstat = {
	.name = "newfstat",
	.num_args = 2,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "statbuf",
	.arg2type = ARG_ADDRESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
                   struct stat __user *, statbuf, int, flag)
 */
#include <fcntl.h>
#include "sanitise.h"

static unsigned long newfstatat_flags[] = {
	0,	// FIXME: WAT?
	AT_SYMLINK_NOFOLLOW,
};

struct syscallentry syscall_newfstatat = {
	.name = "newfstatat",
	.num_args = 4,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_PATHNAME,
	.arg3name = "statbuf",
	.arg3type = ARG_ADDRESS,
	.arg4name = "flag",
	.arg4type = ARG_LIST,
	.arg4list = ARGLIST(newfstatat_flags),
	.group = GROUP_VFS,
};
