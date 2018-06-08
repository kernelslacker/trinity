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
	.arg1name = "which",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(getpriority_which),
	.arg2name = "who",
	.arg2type = ARG_PID,
};
