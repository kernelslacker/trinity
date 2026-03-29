/*
 * SYSCALL_DEFINE2(setgroups, int, gidsetsize, gid_t __user *, grouplist)
 */
#include "sanitise.h"

struct syscallentry syscall_setgroups = {
	.name = "setgroups",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS },
	.argname = { [0] = "gidsetsize", [1] = "grouplist" },
	.low1range = 0,
	.hi1range = 65536,
	.group = GROUP_PROCESS,
};


/*
 * SYSCALL_DEFINE2(getgroups16, int, gidsetsize, old_gid_t __user *, grouplist)
 */

struct syscallentry syscall_setgroups16 = {
	.name = "setgroups16",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS },
	.argname = { [0] = "gidsetsize", [1] = "grouplist" },
	.low1range = 0,
	.hi1range = 65536,
	.group = GROUP_PROCESS,
};
