/*
 * SYSCALL_DEFINE2(pidfd_open, pid_t, pid, unsigned int, flags)
 */
#include "sanitise.h"

static unsigned long pidfd_open_flags[] = {
	0,
};

struct syscallentry syscall_pidfd_open = {
	.name = "pidfd_open",
	.num_args = 2,
	.arg1type = ARG_PID,
	.arg1name = "pid",
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(pidfd_open_flags),
	.rettype = RET_PID_T,
};
