/*
 * SYSCALL_DEFINE2(bdflush, int, func, long, data)
 */
#include "sanitise.h"

struct syscallentry syscall_bdflush = {
	.name = "bdflush",
	.num_args = 2,
	.argtype = { [1] = ARG_ADDRESS },
	.argname = { [0] = "func", [1] = "data" },
	.group = GROUP_PROCESS,
	.flags = NEEDS_ROOT,
};
