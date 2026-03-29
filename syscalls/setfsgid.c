/*
 * SYSCALL_DEFINE1(setfsgid, gid_t, gid)
 */
#include "sanitise.h"

struct syscallentry syscall_setfsgid = {
	.name = "setfsgid",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "gid" },
	.low1range = 0,
	.hi1range = 65535,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE1(setfsgid16, old_gid_t, gid)
 */

struct syscallentry syscall_setfsgid16 = {
	.name = "setfsgid16",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "gid" },
	.low1range = 0,
	.hi1range = 65535,
	.group = GROUP_VFS,
};
