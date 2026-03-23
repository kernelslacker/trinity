/*
 * SYSCALL_DEFINE4(statmount, const struct mnt_id_req __user *, req,
 *		struct statmount __user *, buf, size_t, bufsize,
 *		unsigned int, flags)
 */
#include <linux/mount.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"
#include "compat.h"

#ifndef LSMT_ROOT
#define LSMT_ROOT 0xffffffffffffffff
#endif

#ifndef STATMOUNT_SB_BASIC
#define STATMOUNT_SB_BASIC		0x00000001U
#define STATMOUNT_MNT_BASIC		0x00000002U
#define STATMOUNT_PROPAGATE_FROM	0x00000004U
#define STATMOUNT_MNT_ROOT		0x00000008U
#define STATMOUNT_MNT_POINT		0x00000010U
#define STATMOUNT_FS_TYPE		0x00000020U
#define STATMOUNT_MNT_NS_ID		0x00000040U
#define STATMOUNT_MNT_OPTS		0x00000080U
#endif

static unsigned long statmount_params[] = {
	STATMOUNT_SB_BASIC, STATMOUNT_MNT_BASIC, STATMOUNT_PROPAGATE_FROM,
	STATMOUNT_MNT_ROOT, STATMOUNT_MNT_POINT, STATMOUNT_FS_TYPE,
	STATMOUNT_MNT_NS_ID, STATMOUNT_MNT_OPTS,
};

static void sanitise_statmount(struct syscallrecord *rec)
{
	struct mnt_id_req *req;
	unsigned int i, nbits;
	__u64 param;

	req = (struct mnt_id_req *) get_writable_address(sizeof(*req));
	memset(req, 0, sizeof(*req));

	req->size = MNT_ID_REQ_SIZE_VER0;

	switch (rand() % 3) {
	case 0: req->mnt_id = LSMT_ROOT; break;
	case 1: req->mnt_id = 1; break;
	default: req->mnt_id = rand32(); break;
	}

	/* Build a random combination of STATMOUNT_* request flags. */
	param = 0;
	nbits = 1 + (rand() % ARRAY_SIZE(statmount_params));
	for (i = 0; i < nbits; i++)
		param |= statmount_params[rand() % ARRAY_SIZE(statmount_params)];
	req->param = param;

	rec->a1 = (unsigned long) req;
	rec->a3 = 4096;	/* reasonable output buffer size */
	rec->a4 = 0;		/* flags must be zero */
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
