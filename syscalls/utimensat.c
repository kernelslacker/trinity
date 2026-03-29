/*
 * SYSCALL_DEFINE4(utimensat, int, dfd, const char __user *, filename,
	 struct timespec __user *, utimes, int, flags)
 */
#include <fcntl.h>
#include "sanitise.h"

static unsigned long utimensat_flags[] = {
	AT_SYMLINK_NOFOLLOW,
};

struct syscallentry syscall_utimensat = {
	.name = "utimensat",
	.group = GROUP_TIME,
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_ADDRESS, [3] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "utimes", [3] = "flags" },
	.arg4list = ARGLIST(utimensat_flags),
	.flags = NEED_ALARM,
};
