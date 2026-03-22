/*
 * SYSCALL_DEFINE2(setregid, gid_t, rgid, gid_t, egid)
 */
#include "sanitise.h"

struct syscallentry syscall_setregid = {
	.name = "setregid",
	.num_args = 2,
	.arg1name = "rgid",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = 65535,
	.arg2name = "egid",
	.arg2type = ARG_RANGE,
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
	.arg1name = "rgid",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = 65535,
	.arg2name = "egid",
	.arg2type = ARG_RANGE,
	.low2range = 0,
	.hi2range = 65535,
	.group = GROUP_PROCESS,
};
