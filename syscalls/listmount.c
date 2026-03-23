/*
 * SYSCALL_DEFINE4(listmount, const struct mnt_id_req __user *, req,
 *		u64 __user *, mnt_ids, size_t, nr_mnt_ids,
 *		unsigned int, flags)
 */
#include <linux/mount.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"
#include "compat.h"

#ifndef LISTMOUNT_REVERSE
#define LISTMOUNT_REVERSE	(1 << 0)
#endif

#ifndef LSMT_ROOT
#define LSMT_ROOT 0xffffffffffffffff
#endif

static unsigned long listmount_flags[] = {
	LISTMOUNT_REVERSE,
};

static void sanitise_listmount(struct syscallrecord *rec)
{
	struct mnt_id_req *req;
	__u64 *mnt_ids;
	unsigned int nr;

	req = (struct mnt_id_req *) get_writable_address(sizeof(*req));
	memset(req, 0, sizeof(*req));

	req->size = MNT_ID_REQ_SIZE_VER0;

	switch (rand() % 3) {
	case 0: req->mnt_id = LSMT_ROOT; break;	/* list all mounts */
	case 1: req->mnt_id = 1; break;		/* root mount */
	default: req->mnt_id = rand32(); break;		/* random mount id */
	}

	nr = 1 + (rand() % 64);
	mnt_ids = (__u64 *) get_writable_address(nr * sizeof(*mnt_ids));

	rec->a1 = (unsigned long) req;
	rec->a2 = (unsigned long) mnt_ids;
	rec->a3 = nr;
}

struct syscallentry syscall_listmount = {
	.name = "listmount",
	.num_args = 4,
	.arg1name = "req",
	.arg2name = "mnt_ids",
	.arg3name = "nr_mnt_ids",
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = ARGLIST(listmount_flags),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
	.sanitise = sanitise_listmount,
};
