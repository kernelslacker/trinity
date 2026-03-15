/*
 * SYSCALL_DEFINE3(mseal, unsigned long, start, size_t, len, unsigned long, flags)
 */
#include "sanitise.h"

static void sanitise_mseal(struct syscallrecord *rec)
{
	rec->a3 = 0;	/* no flags defined yet, must be zero */
}

struct syscallentry syscall_mseal = {
	.name = "mseal",
	.num_args = 3,
	.arg1name = "start",
	.arg1type = ARG_MMAP,
	.arg2name = "len",
	.arg2type = ARG_LEN,
	.arg3name = "flags",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VM,
	.sanitise = sanitise_mseal,
};
