/*
 * SYSCALL_DEFINE2(pidfd_open, pid_t, pid, unsigned int, flags)
 */
#include "sanitise.h"

static unsigned long pidfd_getfd_flags[] = {
	0,
};

struct syscallentry syscall_pidfd_getfd = {
	.name = "pidfd_getfd",
	.num_args = 3,
	.arg1name = "pidfd",
	.arg1type = ARG_PID,
	.arg2name = "fd",
	.arg2type = ARG_PID,
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(pidfd_getfd_flags),
	.rettype = RET_PID_T,
};
