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
	.num_args = 2,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "nstype",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(setns_types),
	.flags = NEED_ALARM,
};
