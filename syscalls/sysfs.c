/*
 * SYSCALL_DEFINE3(sysfs, int, option, unsigned long, arg1, unsigned long, arg2)
 */
#include "sanitise.h"

static unsigned long sysfs_options[] = {
	1, 2, 3,
};

struct syscallentry syscall_sysfs = {
	.name = "sysfs",
	.num_args = 3,
	.arg1name = "option",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(sysfs_options),
	.arg2name = "arg1",
	.arg3name = "arg2",
};
