/*
 * SYSCALL_DEFINE1(umask, int, mask)
 */
#include "sanitise.h"

struct syscallentry syscall_umask = {
	.name = "umask",
	.num_args = 1,
	.arg1name = "mask",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = 07777,
	.group = GROUP_PROCESS,
};
