/*
 * SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
	 unsigned long, arg4, unsigned long, arg5)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_prctl = {
	.name = "prctl",
	.flags = AVOID_SYSCALL,
	.num_args = 5,
	.arg1name = "option",
	.arg2name = "arg2",
	.arg3name = "arg3",
	.arg4name = "arg4",
	.arg5name = "arg5",
};
