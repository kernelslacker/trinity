/*
 * SYSCALL_DEFINE3(sysfs, int, option, unsigned long, arg1, unsigned long, arg2)
 */
#include "sanitise.h"

struct syscallentry syscall_sysfs = {
	.name = "sysfs",
	.num_args = 3,
	.arg1name = "option",
	.arg1type = ARG_OP,
	.arg1list = {
		.num = 3,
		.values = { 1, 2, 3 },
	},
	.arg2name = "arg1",
	.arg3name = "arg2",
};
