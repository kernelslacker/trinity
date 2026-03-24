/*
 * SYSCALL_DEFINE2(landlock_restrict_self,
 *                const int, ruleset_fd, const __u32, flags)
 */
#include "sanitise.h"

struct syscallentry syscall_landlock_restrict_self = {
	.name = "landlock_restrict_self",
	.num_args = 2,
	.arg1name = "fd",
	.arg1type = ARG_FD_LANDLOCK,
	.arg2name = "flags",
	.arg2type = ARG_RANGE,
	.low2range = 0,
	.hi2range = 0,
	.group = GROUP_PROCESS,
};
