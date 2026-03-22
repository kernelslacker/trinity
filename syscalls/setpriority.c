/*
 * SYSCALL_DEFINE3(setpriority, int, which, int, who, int, niceval)
 */
#include <sys/resource.h>
#include "sanitise.h"

static unsigned long setpriority_which[] = {
	PRIO_PROCESS, PRIO_PGRP, PRIO_USER,
};

struct syscallentry syscall_setpriority = {
	.name = "setpriority",
	.num_args = 3,
	.arg1name = "which",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(setpriority_which),
	.arg2name = "who",
	.arg3name = "niceval",
};
