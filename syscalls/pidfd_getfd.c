/*
 * SYSCALL_DEFINE3(pidfd_getfd, int, pidfd, int, fd, unsigned int, flags)
 */
#include "sanitise.h"

static unsigned long pidfd_getfd_flags[] = {
	0,
};

struct syscallentry syscall_pidfd_getfd = {
	.name = "pidfd_getfd",
	.num_args = 3,
	.arg1name = "pidfd",
	.arg1type = ARG_FD,
	.arg2name = "fd",
	.arg2type = ARG_FD,
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(pidfd_getfd_flags),
	.rettype = RET_FD,
};
