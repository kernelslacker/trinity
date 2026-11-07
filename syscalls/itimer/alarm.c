/*
 * SYSCALL_DEFINE1(alarm, unsigned int, seconds)
 *
 * returns  the number of seconds remaining until any previously scheduled alarm was due to be delivered,
 *  or zero if there was no previously scheduled
 */
#include "sanitise.h"

struct syscallentry syscall_alarm = {
	/* We rely on a useful alarm for every syscall (AVOID_SYSCALL).
	 * AVOID_REEXEC belt-and-braces so a future flag rework cannot
	 * silently expose this entry to the re-exec step. */
	.flags = AVOID_SYSCALL | AVOID_REEXEC,
	.name = "alarm",
	.group = GROUP_TIME,
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "seconds" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 5,
	.rettype = RET_BORING,
};
