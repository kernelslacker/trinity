/*
 * SYSCALL_DEFINE4(listmount, const struct mnt_id_req __user *, req,
 *		u64 __user *, mnt_ids, size_t, nr_mnt_ids,
 *		unsigned int, flags)
 */
#include "sanitise.h"

static void sanitise_listmount(struct syscallrecord *rec)
{
	rec->a4 = 0;	/* flags must be zero */
}

struct syscallentry syscall_listmount = {
	.name = "listmount",
	.num_args = 4,
	.arg1name = "req",
	.arg1type = ARG_ADDRESS,
	.arg2name = "mnt_ids",
	.arg2type = ARG_ADDRESS,
	.arg3name = "nr_mnt_ids",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
	.sanitise = sanitise_listmount,
};
