/*
 * SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)
 */
#include "sanitise.h"

struct syscallentry syscall_setresuid = {
	.name = "setresuid",
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "ruid", [1] = "euid", [2] = "suid" },
	.low1range = 0,
	.hi1range = 65535,
	.low2range = 0,
	.hi2range = 65535,
	.low3range = 0,
	.hi3range = 65535,
	.group = GROUP_PROCESS,
};

/*
 * SYSCALL_DEFINE3(setresuid16, old_uid_t, ruid, old_uid_t, euid, old_uid_t, suid)
 */

struct syscallentry syscall_setresuid16 = {
	.name = "setresuid16",
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "ruid", [1] = "euid", [2] = "suid" },
	.low1range = 0,
	.hi1range = 65535,
	.low2range = 0,
	.hi2range = 65535,
	.low3range = 0,
	.hi3range = 65535,
	.group = GROUP_PROCESS,
};
