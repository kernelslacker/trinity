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
	.argtype = { [0] = ARG_OP, [1] = ARG_PID },
	.argname = { [0] = "which", [1] = "who" },
	.arg1list = ARGLIST(ioprio_who),
	.group = GROUP_SCHED,
};
