/*
 * SYSCALL_DEFINE2(ioprio_get, int, which, int, who)
 */
#include "sanitise.h"

#ifndef IOPRIO_WHO_PROCESS
#define IOPRIO_WHO_PROCESS	1
#define IOPRIO_WHO_PGRP		2
#define IOPRIO_WHO_USER		3
#endif

static unsigned long ioprio_who[] = {
	IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP, IOPRIO_WHO_USER,
};

struct syscallentry syscall_ioprio_get = {
	.name = "ioprio_get",
	.num_args = 2,
	.arg1name = "which",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(ioprio_who),
	.arg2name = "who",
	.group = GROUP_SCHED,
};
