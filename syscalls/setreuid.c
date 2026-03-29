/*
 * SYSCALL_DEFINE2(setreuid, uid_t, ruid, uid_t, euid)
 */
#include "sanitise.h"

struct syscallentry syscall_setreuid = {
	.name = "setreuid",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE },
	.argname = { [0] = "ruid", [1] = "euid" },
	.low1range = 0,
	.hi1range = 65535,
	.low2range = 0,
	.hi2range = 65535,
	.group = GROUP_PROCESS,
};


/*
 * SYSCALL_DEFINE2(setreuid16, old_uid_t, ruid, old_uid_t, euid)
 */

struct syscallentry syscall_setreuid16 = {
	.name = "setreuid16",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE },
	.argname = { [0] = "ruid", [1] = "euid" },
	.low1range = 0,
	.hi1range = 65535,
	.low2range = 0,
	.hi2range = 65535,
	.group = GROUP_PROCESS,
};
