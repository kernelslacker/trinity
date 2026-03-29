/*
 * SYSCALL_DEFINE3(sysfs, int, option, unsigned long, arg1, unsigned long, arg2)
 */
#include "maps.h"
#include "random.h"
#include "sanitise.h"

static unsigned long sysfs_options[] = {
	1, 2, 3,
};

static void sanitise_sysfs(struct syscallrecord *rec)
{
	switch (rec->a1) {
	case 1:
		/* option 1: arg1 = pointer to fs type name string */
		rec->a2 = (unsigned long) get_address();
		break;
	case 2:
		/* option 2: arg1 = fs type index, arg2 = pointer to buffer */
		rec->a2 = rand() % 32;
		rec->a3 = (unsigned long) get_writable_address(256);
		break;
	case 3:
		/* option 3: returns total number of fs types, no args used */
		break;
	}
}

struct syscallentry syscall_sysfs = {
	.name = "sysfs",
	.num_args = 3,
	.argtype = { [0] = ARG_OP },
	.argname = { [0] = "option", [1] = "arg1", [2] = "arg2" },
	.arg_params[0].list = ARGLIST(sysfs_options),
	.sanitise = sanitise_sysfs,
	.group = GROUP_PROCESS,
};
