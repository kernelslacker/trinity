#include <linux/fs.h>
#include <linux/types.h>

#include <asm/ioctl.h>
#include "ioctls.h"
#include "objects.h"
#include "shm.h"
#include "utils.h"

struct ext4_new_group_input {
	__u32 group;		/* Group number for this data */
	__u64 block_bitmap;	/* Absolute block number of block bitmap */
	__u64 inode_bitmap;	/* Absolute block number of inode bitmap */
	__u64 inode_table;	/* Absolute block number of inode table start */
	__u32 blocks_count;	/* Total number of blocks in this group */
	__u16 reserved_blocks;	/* Number of reserved blocks in this group */
	__u16 unused;
};

struct move_extent {
	__u32 reserved;		/* should be zero */
	__u32 donor_fd;		/* donor file descriptor */
	__u64 orig_start;	/* logical start offset in block for orig */
	__u64 donor_start;	/* logical start offset in block for donor */
	__u64 len;		/* block length to be moved */
	__u64 moved_len;	/* moved block length */
};

#define EXT4_KEY_DESCRIPTOR_SIZE 8
struct ext4_encryption_policy {
	char version;
	char contents_encryption_mode;
	char filenames_encryption_mode;
	char flags;
	char master_key_descriptor[EXT4_KEY_DESCRIPTOR_SIZE];
};

#define EXT4_IOC_GETVERSION             _IOR('f', 3, long)
#define EXT4_IOC_SETVERSION             _IOW('f', 4, long)
#define EXT4_IOC_GETRSVSZ               _IOR('f', 5, long)
#define EXT4_IOC_SETRSVSZ               _IOW('f', 6, long)
#define EXT4_IOC_GROUP_EXTEND           _IOW('f', 7, unsigned long)
#define EXT4_IOC_GROUP_ADD              _IOW('f', 8, struct ext4_new_group_input)
#define EXT4_IOC_MIGRATE                _IO('f', 9)
#define EXT4_IOC_ALLOC_DA_BLKS          _IO('f', 12)
#define EXT4_IOC_MOVE_EXT               _IOWR('f', 15, struct move_extent)
#define EXT4_IOC_RESIZE_FS              _IOW('f', 16, __u64)
#define EXT4_IOC_SWAP_BOOT              _IO('f', 17)
#define EXT4_IOC_PRECACHE_EXTENTS       _IO('f', 18)
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
 * EXT4_IOC_SETRSVSZ, EXT4_IOC_GROUP_EXTEND and EXT4_IOC_RESIZE_FS
 * encode a bare scalar (long / unsigned long / __u64);
 * EXT4_IOC_GET_ENCRYPTION_PWSALT encodes a fixed 16-byte array;
 * EXT4_IOC_MIGRATE, EXT4_IOC_ALLOC_DA_BLKS, EXT4_IOC_SWAP_BOOT and
 * EXT4_IOC_PRECACHE_EXTENTS are _IO() with no arg at all.  All are
 * intentionally absent -- asserting sizeof(struct) against a scalar,
 * a bare array, or a zero _IOC_SIZE would be the wrong shape of
 * check.
 */
IOCTL_SIZE_ASSERT(EXT4_IOC_GROUP_ADD, struct ext4_new_group_input);
IOCTL_SIZE_ASSERT(EXT4_IOC_MOVE_EXT, struct move_extent);
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
};

static const struct ioctl_group ext_grp = {
	.name = "ext[234]",
	.fd_test = ext_fd_test,
	.sanitise = pick_random_ioctl,
	.ioctls = ext_ioctls,
	.ioctls_cnt = ARRAY_SIZE(ext_ioctls),
};

REG_IOCTL_GROUP(ext_grp)
