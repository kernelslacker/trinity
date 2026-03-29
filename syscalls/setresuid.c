/*
 * SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)
 */
#include "sanitise.h"

struct syscallentry syscall_setresuid = {
	.name = "setresuid",
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "ruid", [1] = "euid", [2] = "suid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 65535,
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 65535,
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
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 65535,
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 65535,
	.group = GROUP_PROCESS,
};
