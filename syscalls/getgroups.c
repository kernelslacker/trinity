/*
 * SYSCALL_DEFINE2(getgroups, int, gidsetsize, gid_t __user *, grouplist)
 */
#include <sys/types.h>
#include "sanitise.h"

static void sanitise_getgroups(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, rec->a1 * sizeof(gid_t));
}

struct syscallentry syscall_getgroups = {
	.name = "getgroups",
	.num_args = 2,
	.argtype = { [0] = ARG_LEN, [1] = ARG_ADDRESS },
	.argname = { [0] = "gidsetsize", [1] = "grouplist" },
	.sanitise = sanitise_getgroups,
	.rettype = RET_BORING,
	.group = GROUP_PROCESS,
};


/*
 * SYSCALL_DEFINE2(getgroups16, int, gidsetsize, old_gid_t __user *, grouplist)
 */

struct syscallentry syscall_getgroups16 = {
	.name = "getgroups16",
	.num_args = 2,
	.argtype = { [0] = ARG_LEN, [1] = ARG_ADDRESS },
	.argname = { [0] = "gidsetsize", [1] = "grouplist" },
	.sanitise = sanitise_getgroups,
	.rettype = RET_BORING,
	.group = GROUP_PROCESS,
};
