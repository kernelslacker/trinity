/*
 * SYSCALL_DEFINE3(setpriority, int, which, int, who, int, niceval)
 */
#include <sys/resource.h>
#include "random.h"
#include "sanitise.h"

static unsigned long setpriority_which[] = {
	PRIO_PROCESS, PRIO_PGRP, PRIO_USER,
};

static void sanitise_setpriority(struct syscallrecord *rec)
{
	rec->a3 = (unsigned long)((rand() % 40) - 20);	/* -20 to 19 */
}

struct syscallentry syscall_setpriority = {
	.name = "setpriority",
	.num_args = 3,
	.arg1name = "which",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(setpriority_which),
	.arg2name = "who",
	.arg2type = ARG_PID,
	.arg3name = "niceval",
	.sanitise = sanitise_setpriority,
	.group = GROUP_SCHED,
};
