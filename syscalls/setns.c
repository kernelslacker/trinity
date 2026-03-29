/*
 * SYSCALL_DEFINE2(setns, int, fd, int, nstype)
 */
#include <sched.h>
#include "sanitise.h"

static unsigned long setns_types[] = {
	0, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWUTS,
};

struct syscallentry syscall_setns= {
	.name = "setns",
	.group = GROUP_PROCESS,
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "nstype" },
	.arg2list = ARGLIST(setns_types),
	.flags = NEED_ALARM,
};
