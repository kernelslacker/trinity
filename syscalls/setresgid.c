/*
 * SYSCALL_DEFINE3(setresgid, gid_t, rgid, gid_t, egid, gid_t, sgid)
 */
#include "sanitise.h"

struct syscallentry syscall_setresgid = {
	.name = "setresgid",
	.num_args = 3,
	.arg1name = "rgid",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = 65535,
	.arg2name = "egid",
	.arg2type = ARG_RANGE,
	.low2range = 0,
	.hi2range = 65535,
	.arg3name = "sgid",
	.arg3type = ARG_RANGE,
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
	.arg1name = "rgid",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = 65535,
	.arg2name = "egid",
	.arg2type = ARG_RANGE,
	.low2range = 0,
	.hi2range = 65535,
	.arg3name = "sgid",
	.arg3type = ARG_RANGE,
	.low3range = 0,
	.hi3range = 65535,
	.group = GROUP_PROCESS,
};
