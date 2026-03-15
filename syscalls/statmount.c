/*
 * SYSCALL_DEFINE4(statmount, const struct mnt_id_req __user *, req,
 *		struct statmount __user *, buf, size_t, bufsize,
 *		unsigned int, flags)
 */
#include "sanitise.h"

static void sanitise_statmount(struct syscallrecord *rec)
{
	rec->a4 = 0;	/* flags must be zero */
}

struct syscallentry syscall_statmount = {
	.name = "statmount",
	.num_args = 4,
	.arg1name = "req",
	.arg1type = ARG_ADDRESS,
	.arg2name = "buf",
	.arg2type = ARG_ADDRESS,
	.arg3name = "bufsize",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
	.sanitise = sanitise_statmount,
};
