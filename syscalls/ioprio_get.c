/*
 * SYSCALL_DEFINE2(ioprio_get, int, which, int, who)
 */
#include <linux/ioprio.h>
#include "sanitise.h"

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
	.arg2type = ARG_PID,
	.group = GROUP_SCHED,
};
