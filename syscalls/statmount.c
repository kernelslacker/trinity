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
#define STATMOUNT_FS_SUBTYPE		0x00000100U
#define STATMOUNT_SB_SOURCE		0x00000200U
#define STATMOUNT_OPT_ARRAY		0x00000400U
#define STATMOUNT_OPT_SEC_ARRAY		0x00000800U
#endif
/* statmount() param mask bits added in Linux v6.15. */
#ifndef STATMOUNT_SUPPORTED_MASK
#define STATMOUNT_SUPPORTED_MASK	0x00001000U
#endif
/* statmount() param mask bits added in Linux v7.0. */
#ifndef STATMOUNT_MNT_UIDMAP
#define STATMOUNT_MNT_UIDMAP		0x00002000U
#define STATMOUNT_MNT_GIDMAP		0x00004000U
#endif
/* statmount() syscall flags bit added in Linux v7.0. */
#ifndef STATMOUNT_BY_FD
#define STATMOUNT_BY_FD			0x00000001U
#endif

static unsigned long statmount_params[] = {
	STATMOUNT_SB_BASIC, STATMOUNT_MNT_BASIC, STATMOUNT_PROPAGATE_FROM,
	STATMOUNT_MNT_ROOT, STATMOUNT_MNT_POINT, STATMOUNT_FS_TYPE,
	STATMOUNT_MNT_NS_ID, STATMOUNT_MNT_OPTS,
#ifdef STATMOUNT_FS_SUBTYPE
	STATMOUNT_FS_SUBTYPE, STATMOUNT_SB_SOURCE,
#endif
#ifdef STATMOUNT_OPT_ARRAY
	STATMOUNT_OPT_ARRAY, STATMOUNT_OPT_SEC_ARRAY,
#endif
#ifdef STATMOUNT_SUPPORTED_MASK
	STATMOUNT_SUPPORTED_MASK,
#endif
#ifdef STATMOUNT_MNT_UIDMAP
	STATMOUNT_MNT_UIDMAP, STATMOUNT_MNT_GIDMAP,
#endif
};

static void sanitise_statmount(struct syscallrecord *rec)
{
	struct mnt_id_req *req;
	unsigned int i, nbits;
	__u64 param;

	req = (struct mnt_id_req *) get_writable_struct(sizeof(*req));
	if (!req)
		return;
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
	rec->a4 = ONE_IN(4) ? STATMOUNT_BY_FD : 0;

	/*
	 * buf (a2) is the kernel's writeback target for struct statmount
	 * plus its variable-length tail (mount opts, fs type strings, etc).
	 * The sanitise above declared a3 = 4096 as the buffer size; mirror
	 * that as the avoid_shared_buffer length.  ARG_ADDRESS draws from
	 * the random pool, so a fuzzed pointer can land inside an
	 * alloc_shared region.
	 */
	avoid_shared_buffer(&rec->a2, rec->a3);
}

struct syscallentry syscall_statmount = {
	.name = "statmount",
	.num_args = 4,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "req", [1] = "buf", [2] = "bufsize", [3] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
	.sanitise = sanitise_statmount,
};
