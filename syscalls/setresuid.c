/*
 * SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)
 */
#include "sanitise.h"

struct syscallentry syscall_setresuid = {
	.name = "setresuid",
	.num_args = 3,
	.arg1name = "ruid",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = 65535,
	.arg2name = "euid",
	.arg2type = ARG_RANGE,
	.low2range = 0,
	.hi2range = 65535,
	.arg3name = "suid",
	.arg3type = ARG_RANGE,
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
	.arg1name = "ruid",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = 65535,
	.arg2name = "euid",
	.arg2type = ARG_RANGE,
	.low2range = 0,
	.hi2range = 65535,
	.arg3name = "suid",
	.arg3type = ARG_RANGE,
	.low3range = 0,
	.hi3range = 65535,
	.group = GROUP_PROCESS,
};
