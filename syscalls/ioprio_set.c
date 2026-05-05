/*
 * SYSCALL_DEFINE3(ioprio_set, int, which, int, who, int, ioprio)
 */
#include <linux/ioprio.h>
#include "sanitise.h"
#include "random.h"

static unsigned long ioprio_who[] = {
	IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP, IOPRIO_WHO_USER,
};

static void sanitise_ioprio_set(struct syscallrecord *rec)
{
	unsigned int class, level;

	/* ioprio encodes class in bits 15:13, level in bits 12:0. */
	switch (rand() % 5) {
	case 0: class = IOPRIO_CLASS_NONE; break;
	case 1: class = IOPRIO_CLASS_RT; break;
	case 2: class = IOPRIO_CLASS_BE; break;
	case 3: class = IOPRIO_CLASS_IDLE; break;
	case 4: class = IOPRIO_CLASS_INVALID; break;
	default: class = IOPRIO_CLASS_BE; break;
	}

	level = rand() % 8;

	rec->a3 = (class << IOPRIO_CLASS_SHIFT) | level;
}

struct syscallentry syscall_ioprio_set = {
	.name = "ioprio_set",
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_PID },
	.argname = { [0] = "which", [1] = "who", [2] = "ioprio" },
	.arg_params[0].list = ARGLIST(ioprio_who),
	.sanitise = sanitise_ioprio_set,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_SCHED,
};
