/*
 * SYSCALL_DEFINE1(timer_getoverrun, timer_t, timer_id)
 */
#include <limits.h>
#include "sanitise.h"
#include "trinity.h"

static void post_timer_getoverrun(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;

	if (ret < 0 || ret > INT_MAX)
		output(0, "timer_getoverrun oracle: returned %ld is out of range (must be 0..INT_MAX or -1)\n",
			ret);
}

struct syscallentry syscall_timer_getoverrun = {
	.name = "timer_getoverrun",
	.group = GROUP_TIME,
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "timer_id" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 31,
	.post = post_timer_getoverrun,
};
