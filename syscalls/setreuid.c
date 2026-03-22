/*
 * SYSCALL_DEFINE2(setreuid, uid_t, ruid, uid_t, euid)
 */
#include "sanitise.h"

struct syscallentry syscall_setreuid = {
	.name = "setreuid",
	.num_args = 2,
	.arg1name = "ruid",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = 65535,
	.arg2name = "euid",
	.arg2type = ARG_RANGE,
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
	.arg1name = "ruid",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = 65535,
	.arg2name = "euid",
	.arg2type = ARG_RANGE,
	.low2range = 0,
	.hi2range = 65535,
	.group = GROUP_PROCESS,
};
