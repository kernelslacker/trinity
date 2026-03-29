/*
 * SYSCALL_DEFINE2(setgroups, int, gidsetsize, gid_t __user *, grouplist)
 */
#include <grp.h>
#include "random.h"
#include "sanitise.h"

static void sanitise_setgroups(struct syscallrecord *rec)
{
	int count = (int) rec->a1;
	gid_t *list;
	int i;

	if (count <= 0 || count > 65536)
		return;

	list = (gid_t *) get_writable_address(count * sizeof(gid_t));
	for (i = 0; i < count; i++)
		list[i] = (gid_t) rand();

	rec->a2 = (unsigned long) list;
}

struct syscallentry syscall_setgroups = {
	.name = "setgroups",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS },
	.argname = { [0] = "gidsetsize", [1] = "grouplist" },
	.low1range = 0,
	.hi1range = 65536,
	.sanitise = sanitise_setgroups,
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
