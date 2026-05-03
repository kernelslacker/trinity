/*
 * SYSCALL_DEFINE3(mseal, unsigned long, start, size_t, len, unsigned long, flags)
 */
#include "sanitise.h"

static void sanitise_mseal(struct syscallrecord *rec)
{
	if (range_overlaps_shared(rec->a1, rec->a2)) {
		rec->a1 = 0;
		rec->a2 = 0;
	}

	rec->a3 = 0;	/* no flags defined yet, must be zero */
}

struct syscallentry syscall_mseal = {
	.name = "mseal",
	.num_args = 3,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN },
	.argname = { [0] = "start", [1] = "len", [2] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VM,
	.sanitise = sanitise_mseal,
};
