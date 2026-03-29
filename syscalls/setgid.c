/*
 * SYSCALL_DEFINE1(setgid, gid_t, gid)
 */
#include "sanitise.h"

struct syscallentry syscall_setgid = {
	.name = "setgid",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "gid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.group = GROUP_PROCESS,
};


/*
 * SYSCALL_DEFINE1(setgid16, old_gid_t, gid)
 */

struct syscallentry syscall_setgid16 = {
	.name = "setgid16",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "gid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.group = GROUP_PROCESS,
};
