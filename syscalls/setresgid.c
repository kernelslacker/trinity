/*
 * SYSCALL_DEFINE3(setresgid, gid_t, rgid, gid_t, egid, gid_t, sgid)
 */
#include "sanitise.h"

struct syscallentry syscall_setresgid = {
	.name = "setresgid",
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "rgid", [1] = "egid", [2] = "sgid" },
	.low1range = 0,
	.hi1range = 65535,
	.low2range = 0,
	.hi2range = 65535,
	.low3range = 0,
	.hi3range = 65535,
	.group = GROUP_PROCESS,
};


/*
 * SYSCALL_DEFINE3(setresgid16, old_gid_t, rgid, old_gid_t, egid, old_gid_t, sgid)
 */

struct syscallentry syscall_setresgid16 = {
	.name = "setresgid16",
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "rgid", [1] = "egid", [2] = "sgid" },
	.low1range = 0,
	.hi1range = 65535,
	.low2range = 0,
	.hi2range = 65535,
	.low3range = 0,
	.hi3range = 65535,
	.group = GROUP_PROCESS,
};
