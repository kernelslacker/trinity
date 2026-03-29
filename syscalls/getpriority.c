/*
 * SYSCALL_DEFINE2(getpriority, int, which, int, who)
 */

#include <sys/time.h>
#include <sys/resource.h>
#include "sanitise.h"

static unsigned long getpriority_which[] = {
	PRIO_PROCESS, PRIO_PGRP, PRIO_USER,
};

struct syscallentry syscall_getpriority = {
	.name = "getpriority",
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_PID },
	.argname = { [0] = "which", [1] = "who" },
	.arg_params[0].list = ARGLIST(getpriority_which),
	.group = GROUP_SCHED,
};
