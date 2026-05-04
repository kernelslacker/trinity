/*
 * SYSCALL_DEFINE2(getpriority, int, which, int, who)
 */

#include <sys/time.h>
#include <sys/resource.h>
#include "sanitise.h"
#include "trinity.h"

static unsigned long getpriority_which[] = {
	PRIO_PROCESS, PRIO_PGRP, PRIO_USER,
};

static void post_getpriority(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;

	if (ret < 1 || ret > 40)
		output(0, "getpriority oracle: returned %ld is out of range (must be 1..40 or -1)\n",
			ret);
}

struct syscallentry syscall_getpriority = {
	.name = "getpriority",
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_PID },
	.argname = { [0] = "which", [1] = "who" },
	.arg_params[0].list = ARGLIST(getpriority_which),
	.group = GROUP_SCHED,
	.post = post_getpriority,
};
