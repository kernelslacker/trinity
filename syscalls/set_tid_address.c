/*
 * SYSCALL_DEFINE1(set_tid_address, int __user *, tidptr)
 */
#include "sanitise.h"

struct syscallentry syscall_set_tid_address = {
	.name = "set_tid_address",
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "tidptr" },
	.flags = AVOID_SYSCALL,
	.group = GROUP_PROCESS,
};
