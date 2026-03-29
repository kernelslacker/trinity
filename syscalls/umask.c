/*
 * SYSCALL_DEFINE1(umask, int, mask)
 */
#include "sanitise.h"

struct syscallentry syscall_umask = {
	.name = "umask",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "mask" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 07777,
	.group = GROUP_PROCESS,
};
