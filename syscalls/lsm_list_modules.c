/*
 * SYSCALL_DEFINE3(lsm_list_modules, u64 __user *, ids, u32 __user *, size,
 *		u32, flags)
 */
#include "sanitise.h"

static void sanitise_lsm_list_modules(struct syscallrecord *rec)
{
	rec->a3 = 0;	/* flags must be zero */
}

struct syscallentry syscall_lsm_list_modules = {
	.name = "lsm_list_modules",
	.num_args = 3,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "ids", [1] = "size", [2] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_lsm_list_modules,
	.group = GROUP_PROCESS,
};
