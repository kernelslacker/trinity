/*
 * SYSCALL_DEFINE1(umask, int, mask)
 */
#include "sanitise.h"

struct syscallentry syscall_umask = {
	.name = "umask",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "mask" },
	.low1range = 0,
	.hi1range = 07777,
	.group = GROUP_PROCESS,
};
