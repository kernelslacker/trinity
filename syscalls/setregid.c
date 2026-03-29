/*
 * SYSCALL_DEFINE2(setregid, gid_t, rgid, gid_t, egid)
 */
#include "sanitise.h"

struct syscallentry syscall_setregid = {
	.name = "setregid",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE },
	.argname = { [0] = "rgid", [1] = "egid" },
	.low1range = 0,
	.hi1range = 65535,
	.low2range = 0,
	.hi2range = 65535,
	.group = GROUP_PROCESS,
};

/*
 * SYSCALL_DEFINE2(setregid16, old_gid_t, rgid, old_gid_t, egid)
 */

struct syscallentry syscall_setregid16 = {
	.name = "setregid16",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE },
	.argname = { [0] = "rgid", [1] = "egid" },
	.low1range = 0,
	.hi1range = 65535,
	.low2range = 0,
	.hi2range = 65535,
	.group = GROUP_PROCESS,
};
