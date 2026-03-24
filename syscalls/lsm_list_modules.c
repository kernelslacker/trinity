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
	.arg1name = "ids",
	.arg1type = ARG_NON_NULL_ADDRESS,
	.arg2name = "size",
	.arg2type = ARG_NON_NULL_ADDRESS,
	.arg3name = "flags",
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_lsm_list_modules,
	.group = GROUP_PROCESS,
};
