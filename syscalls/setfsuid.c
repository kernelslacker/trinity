/*
 * SYSCALL_DEFINE1(setfsuid, uid_t, uid)
 */
#include "sanitise.h"

struct syscallentry syscall_setfsuid = {
	.name = "setfsuid",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "uid" },
	.low1range = 0,
	.hi1range = 65535,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE1(setfsuid16, old_uid_t, uid)
 */

struct syscallentry syscall_setfsuid16 = {
	.name = "setfsuid16",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "uid" },
	.low1range = 0,
	.hi1range = 65535,
	.group = GROUP_VFS,
};
