/*
 * SYSCALL_DEFINE2(ioprio_get, int, which, int, who)
 */
#include <linux/ioprio.h>
#include "sanitise.h"
#include "trinity.h"

static unsigned long ioprio_who[] = {
	IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP, IOPRIO_WHO_USER,
};

static void post_ioprio_get(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;

	if (ret < 0 || ret > 0xFFFF)
		output(0, "ioprio_get oracle: returned %ld is out of range (must fit in 16 bits or be -1)\n",
			ret);
}

struct syscallentry syscall_ioprio_get = {
	.name = "ioprio_get",
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_PID },
	.argname = { [0] = "which", [1] = "who" },
	.arg_params[0].list = ARGLIST(ioprio_who),
	.group = GROUP_SCHED,
	.post = post_ioprio_get,
};
