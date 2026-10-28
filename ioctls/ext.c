#include <linux/fs.h>
#include <linux/types.h>

#include <asm/ioctl.h>
#include <string.h>
#include "ioctls.h"
#include "kernel/ext4.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

/*
 * <linux/ext4.h> leaves codes 19 to 39 to fscrypt, so it has none of these:
 * the FS_IOC_*ENCRYPTION requests under the ext4 names they once had.
 */
#define EXT4_KEY_DESCRIPTOR_SIZE 8
struct ext4_encryption_policy {
	char version;
	char contents_encryption_mode;
	char filenames_encryption_mode;
	char flags;
	char master_key_descriptor[EXT4_KEY_DESCRIPTOR_SIZE];
};

#define EXT4_IOC_SET_ENCRYPTION_POLICY  _IOR('f', 19, struct ext4_encryption_policy)
#define EXT4_IOC_GET_ENCRYPTION_PWSALT  _IOW('f', 20, __u8[16])
#define EXT4_IOC_GET_ENCRYPTION_POLICY  _IOW('f', 21, struct ext4_encryption_policy)

/*
 * Compile-time: every fixed-shape ext ioctl command whose arg is a
 * kernel struct must have sizeof(struct) matching the _IOC_SIZE
 * encoded in its request bits.  A mismatch means one of the local
 * struct definitions or the matching _IO* macro moved without the
 * other, and the kernel will copy_from_user() / copy_to_user() a
 * different number of bytes than we prepared -- either short of the
 * kernel's copy or past it.  EXT4_IOC_SET_ENCRYPTION_POLICY and
 * EXT4_IOC_GET_ENCRYPTION_POLICY both take ext4_encryption_policy
 * and get one assert each -- the two sides can drift independently
 * in a header refactor.
 *
 * EXT4_IOC_GETVERSION, EXT4_IOC_SETVERSION, EXT4_IOC_GETRSVSZ,
 * EXT4_IOC_SETRSVSZ, EXT4_IOC_GROUP_EXTEND, EXT4_IOC_RESIZE_FS,
 * EXT4_IOC_GETSTATE and EXT4_IOC_CHECKPOINT encode a bare scalar
 * (long / unsigned long / __u64 / __u32);
 * EXT4_IOC_GET_ENCRYPTION_PWSALT encodes a fixed 16-byte array;
 * EXT4_IOC_MIGRATE, EXT4_IOC_ALLOC_DA_BLKS, EXT4_IOC_SWAP_BOOT,
 * EXT4_IOC_PRECACHE_EXTENTS and EXT4_IOC_CLEAR_ES_CACHE are _IO() with
 * no arg at all.  All are intentionally absent -- asserting
 * sizeof(struct) against a scalar, a bare array, or a zero _IOC_SIZE
 * would be the wrong shape of check.
 */
IOCTL_SIZE_ASSERT(EXT4_IOC_GROUP_ADD, struct ext4_new_group_input);
IOCTL_SIZE_ASSERT(EXT4_IOC_MOVE_EXT, struct move_extent);
IOCTL_SIZE_ASSERT(EXT4_IOC_GET_ES_CACHE, struct fiemap);
IOCTL_SIZE_ASSERT(EXT4_IOC_GETFSUUID, struct fsuuid);
IOCTL_SIZE_ASSERT(EXT4_IOC_GET_TUNE_SB_PARAM, struct ext4_tune_sb_params);
IOCTL_SIZE_ASSERT(EXT4_IOC_SET_ENCRYPTION_POLICY, struct ext4_encryption_policy);
IOCTL_SIZE_ASSERT(EXT4_IOC_GET_ENCRYPTION_POLICY, struct ext4_encryption_policy);

static int ext_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_TESTFILE);

	for_each_obj(head, obj, idx) {
		if (obj->testfileobj.fd == fd)
			return 0;
	}

	return -1;
}

/* What ext4_ioctl_getuuid() copies out after the header. */
#define EXT4_UUID_SIZE	16

/*
 * ext4_ioctl_getuuid() answers a length of 0 with the uuid's size, a length
 * under 16 or any flag -EINVAL, and otherwise copies 16 bytes out after the
 * header.  struct fsuuid ends in a flexible array, which the encoded size
 * leaves out, so the buffer is made as long as that copy.
 */
static void sanitise_getfsuuid(struct syscallrecord *rec)
{
	size_t size = sizeof(struct fsuuid) + EXT4_UUID_SIZE;
	struct fsuuid *u = get_writable_struct(size);

	if (!u)
		return;
	memset(u, 0, size);

	switch (rnd_modulo_u32(8)) {
	case 0:
		break;
	case 1:
		u->fsu_len = 1 + rnd_modulo_u32(EXT4_UUID_SIZE - 1);
		break;
	case 2:
		u->fsu_len = EXT4_UUID_SIZE + 1 + rnd_modulo_u32(240);
		break;
	default:
		u->fsu_len = EXT4_UUID_SIZE;
		break;
	}
	if (ONE_IN(16))
		u->fsu_flags = 1 + rnd_modulo_u32(255);
	rec->a3 = (unsigned long) u;
}

/* The most extents EXT4_IOC_GET_ES_CACHE gets room for after its header. */
#define ES_CACHE_EXTENTS_MAX	32

/*
 * ext4_ioctl_get_es_cache() reads the fiemap header and fills as many
 * extents after it as fm_extent_count allows, which the encoded size, the
 * header's, does not cover: the buffer is made as long as the count needs.
 * fiemap_prep() answers a length of 0 -EINVAL and a flag other than SYNC
 * -EBADR, and ext4_get_es_cache() takes CACHE first.
 */
static void sanitise_get_es_cache(struct syscallrecord *rec)
{
	static const __u32 flags[] = {
		0,
		FIEMAP_FLAG_SYNC,
		FIEMAP_FLAG_CACHE,
		FIEMAP_FLAG_SYNC | FIEMAP_FLAG_CACHE,
	};
	unsigned int count = rnd_modulo_u32(ES_CACHE_EXTENTS_MAX + 1);
	size_t size = sizeof(struct fiemap) +
		      (size_t) count * sizeof(struct fiemap_extent);
	struct fiemap *fm = get_writable_struct(size);

	if (!fm)
		return;
	memset(fm, 0, size);

	fm->fm_start = ONE_IN(16) ? rnd_u64() :
		       (__u64) rnd_modulo_u32(1024) * page_size;

	switch (rnd_modulo_u32(8)) {
	case 0:
		break;
	case 1:
		fm->fm_length = FIEMAP_MAX_OFFSET;
		break;
	default:
		fm->fm_length = (__u64) (1 + rnd_modulo_u32(1024)) * page_size;
		break;
	}

	fm->fm_flags = ONE_IN(10) ? rnd_u32() : RAND_ARRAY(flags);
	fm->fm_extent_count = count;
	rec->a3 = (unsigned long) fm;
}

/*
 * ext4_ioctl_checkpoint() flushes the journal, and with ZEROOUT or DISCARD
 * zeroes or discards all of it, on the filesystem the testfile is on, which
 * is the box's own: heavy I/O under a lock that stalls every writer.  A
 * flag word that passes the kernel's checks, no bit it does not know and not
 * ZEROOUT and DISCARD together, gets DRY_RUN, so the kernel returns as soon
 * as they pass, and the rest are words the checks refuse: no word does the
 * work.  The checks come after the CAP_SYS_ADMIN test, which a child fails,
 * so this guards a child that has kept the capability.
 */
static void sanitise_checkpoint(struct syscallrecord *rec)
{
	__u32 *flags = get_writable_struct(sizeof(*flags));

	if (!flags)
		return;

	switch (rnd_modulo_u32(4)) {
	case 0:
		*flags = EXT4_IOC_CHECKPOINT_FLAG_DRY_RUN;
		break;
	case 1:
		*flags = EXT4_IOC_CHECKPOINT_FLAG_DRY_RUN |
			 EXT4_IOC_CHECKPOINT_FLAG_DISCARD;
		break;
	case 2:
		*flags = EXT4_IOC_CHECKPOINT_FLAG_DRY_RUN |
			 EXT4_IOC_CHECKPOINT_FLAG_ZEROOUT;
		break;
	default:
		if (RAND_BOOL())
			*flags = EXT4_IOC_CHECKPOINT_FLAG_DISCARD |
				 EXT4_IOC_CHECKPOINT_FLAG_ZEROOUT |
				 (rnd_u32() & EXT4_IOC_CHECKPOINT_FLAG_DRY_RUN);
		else
			*flags = rnd_u32() | (1U << 31);
		break;
	}
	rec->a3 = (unsigned long) flags;
}

static void ext_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case EXT4_IOC_GETFSUUID:
		sanitise_getfsuuid(rec);
		break;
	case EXT4_IOC_GET_ES_CACHE:
		sanitise_get_es_cache(rec);
		break;
	case EXT4_IOC_CHECKPOINT:
		sanitise_checkpoint(rec);
		break;
	default:
		break;
	}
}

static const struct ioctl ext_ioctls[] = {
	{ .name = "EXT4_IOC_GETVERSION", .request = EXT4_IOC_GETVERSION, },
	{ .name = "EXT4_IOC_SETVERSION", .request = EXT4_IOC_SETVERSION, },
	{ .name = "EXT4_IOC_GETRSVSZ", .request = EXT4_IOC_GETRSVSZ, },
	{ .name = "EXT4_IOC_SETRSVSZ", .request = EXT4_IOC_SETRSVSZ, },
	{ .name = "EXT4_IOC_GROUP_EXTEND", .request = EXT4_IOC_GROUP_EXTEND, },
	{ .name = "EXT4_IOC_GROUP_ADD", .request = EXT4_IOC_GROUP_ADD, },
	{ .name = "EXT4_IOC_MIGRATE", .request = EXT4_IOC_MIGRATE, },
	{ .name = "EXT4_IOC_ALLOC_DA_BLKS", .request = EXT4_IOC_ALLOC_DA_BLKS, },
	{ .name = "EXT4_IOC_MOVE_EXT", .request = EXT4_IOC_MOVE_EXT, },
	{ .name = "EXT4_IOC_RESIZE_FS", .request = EXT4_IOC_RESIZE_FS, },
	{ .name = "EXT4_IOC_SWAP_BOOT", .request = EXT4_IOC_SWAP_BOOT, },
	{ .name = "EXT4_IOC_PRECACHE_EXTENTS", .request = EXT4_IOC_PRECACHE_EXTENTS, },
	{ .name = "EXT4_IOC_SET_ENCRYPTION_POLICY", .request = EXT4_IOC_SET_ENCRYPTION_POLICY, },
	{ .name = "EXT4_IOC_GET_ENCRYPTION_PWSALT", .request = EXT4_IOC_GET_ENCRYPTION_PWSALT, },
	{ .name = "EXT4_IOC_GET_ENCRYPTION_POLICY", .request = EXT4_IOC_GET_ENCRYPTION_POLICY, },
	{ .name = "EXT4_IOC_CLEAR_ES_CACHE", .request = EXT4_IOC_CLEAR_ES_CACHE, },
	{ .name = "EXT4_IOC_GETSTATE", .request = EXT4_IOC_GETSTATE, },
	{ .name = "EXT4_IOC_GET_ES_CACHE", .request = EXT4_IOC_GET_ES_CACHE, },
	{ .name = "EXT4_IOC_CHECKPOINT", .request = EXT4_IOC_CHECKPOINT, },
	{ .name = "EXT4_IOC_GETFSUUID", .request = EXT4_IOC_GETFSUUID, },
	{ .name = "EXT4_IOC_GET_TUNE_SB_PARAM", .request = EXT4_IOC_GET_TUNE_SB_PARAM, },
	/*
	 * EXT4_IOC_SHUTDOWN, EXT4_IOC_SETFSUUID and EXT4_IOC_SET_TUNE_SB_PARAM
	 * stay out: they take the filesystem down or rewrite its superblock.
	 */
};

static const struct ioctl_group ext_grp = {
	.name = "ext[234]",
	.fd_test = ext_fd_test,
	.sanitise = ext_sanitise,
	.cmd_held = true,
	.ioctls = ext_ioctls,
	.ioctls_cnt = ARRAY_SIZE(ext_ioctls),
};

REG_IOCTL_GROUP(ext_grp)
