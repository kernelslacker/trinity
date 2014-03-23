/*
 * SYSCALL_DEFINE2(getgroups, int, gidsetsize, gid_t __user *, grouplist)
 */
#include "sanitise.h"

struct syscallentry syscall_getgroups = {
	.name = "getgroups",
	.num_args = 2,
	.arg1name = "gidsetsize",
	.arg2type = ARG_ADDRESS,
	.arg2name = "grouplist",
	.rettype = RET_BORING,
};


/*
 * SYSCALL_DEFINE2(getgroups16, int, gidsetsize, old_gid_t __user *, grouplist)
 */

struct syscallentry syscall_getgroups16 = {
	.name = "getgroups16",
	.num_args = 2,
	.arg1name = "gidsetsize",
	.arg2type = ARG_ADDRESS,
	.arg2name = "grouplist",
	.rettype = RET_BORING,
};
