#pragma once

/*
 * The ext4 ioctls of <linux/ext4.h>.  A kernel-headers package may not ship
 * the header, or may ship it without the later requests, so each request has
 * an #ifndef fallback, and a request that encodes a struct brings the struct
 * under the same guard.
 */
#if __has_include(<linux/ext4.h>)
#include <linux/ext4.h>
#endif
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/types.h>

#ifndef EXT4_IOC_GETVERSION
#define EXT4_IOC_GETVERSION		_IOR('f', 3, long)
#endif
#ifndef EXT4_IOC_SETVERSION
#define EXT4_IOC_SETVERSION		_IOW('f', 4, long)
#endif
#ifndef EXT4_IOC_GETRSVSZ
#define EXT4_IOC_GETRSVSZ		_IOR('f', 5, long)
#endif
#ifndef EXT4_IOC_SETRSVSZ
#define EXT4_IOC_SETRSVSZ		_IOW('f', 6, long)
#endif
#ifndef EXT4_IOC_GROUP_EXTEND
#define EXT4_IOC_GROUP_EXTEND		_IOW('f', 7, unsigned long)
#endif

#ifndef EXT4_IOC_GROUP_ADD
struct ext4_new_group_input {
	__u32 group;		/* Group number for this data */
	__u64 block_bitmap;	/* Absolute block number of block bitmap */
	__u64 inode_bitmap;	/* Absolute block number of inode bitmap */
	__u64 inode_table;	/* Absolute block number of inode table start */
	__u32 blocks_count;	/* Total number of blocks in this group */
	__u16 reserved_blocks;	/* Number of reserved blocks in this group */
	__u16 unused;
};
#define EXT4_IOC_GROUP_ADD		_IOW('f', 8, struct ext4_new_group_input)
#endif

#ifndef EXT4_IOC_MIGRATE
#define EXT4_IOC_MIGRATE		_IO('f', 9)
#endif
#ifndef EXT4_IOC_ALLOC_DA_BLKS
#define EXT4_IOC_ALLOC_DA_BLKS		_IO('f', 12)
#endif

#ifndef EXT4_IOC_MOVE_EXT
struct move_extent {
	__u32 reserved;		/* should be zero */
	__u32 donor_fd;		/* donor file descriptor */
	__u64 orig_start;	/* logical start offset in block for orig */
	__u64 donor_start;	/* logical start offset in block for donor */
	__u64 len;		/* block length to be moved */
	__u64 moved_len;	/* moved block length */
};
#define EXT4_IOC_MOVE_EXT		_IOWR('f', 15, struct move_extent)
#endif

#ifndef EXT4_IOC_RESIZE_FS
#define EXT4_IOC_RESIZE_FS		_IOW('f', 16, __u64)
#endif
#ifndef EXT4_IOC_SWAP_BOOT
#define EXT4_IOC_SWAP_BOOT		_IO('f', 17)
#endif
#ifndef EXT4_IOC_PRECACHE_EXTENTS
#define EXT4_IOC_PRECACHE_EXTENTS	_IO('f', 18)
#endif
#ifndef EXT4_IOC_CLEAR_ES_CACHE
#define EXT4_IOC_CLEAR_ES_CACHE		_IO('f', 40)
#endif
#ifndef EXT4_IOC_GETSTATE
#define EXT4_IOC_GETSTATE		_IOW('f', 41, __u32)
#endif
#ifndef EXT4_IOC_GET_ES_CACHE
#define EXT4_IOC_GET_ES_CACHE		_IOWR('f', 42, struct fiemap)
#endif

#ifndef EXT4_IOC_CHECKPOINT
#define EXT4_IOC_CHECKPOINT		_IOW('f', 43, __u32)
#define EXT4_IOC_CHECKPOINT_FLAG_DISCARD	0x1
#define EXT4_IOC_CHECKPOINT_FLAG_ZEROOUT	0x2
#define EXT4_IOC_CHECKPOINT_FLAG_DRY_RUN	0x4
#define EXT4_IOC_CHECKPOINT_FLAG_VALID		(EXT4_IOC_CHECKPOINT_FLAG_DISCARD | \
						EXT4_IOC_CHECKPOINT_FLAG_ZEROOUT | \
						EXT4_IOC_CHECKPOINT_FLAG_DRY_RUN)
#endif

#ifndef EXT4_IOC_GETFSUUID
struct fsuuid {
	__u32       fsu_len;
	__u32       fsu_flags;
	__u8        fsu_uuid[];
};
#define EXT4_IOC_GETFSUUID		_IOR('f', 44, struct fsuuid)
#endif
#ifndef EXT4_IOC_SETFSUUID
#define EXT4_IOC_SETFSUUID		_IOW('f', 44, struct fsuuid)
#endif

#ifndef EXT4_IOC_GET_TUNE_SB_PARAM
struct ext4_tune_sb_params {
	__u32 set_flags;
	__u32 checkinterval;
	__u16 errors_behavior;
	__u16 mnt_count;
	__u16 max_mnt_count;
	__u16 raid_stride;
	__u64 last_check_time;
	__u64 reserved_blocks;
	__u64 blocks_count;
	__u32 default_mnt_opts;
	__u32 reserved_uid;
	__u32 reserved_gid;
	__u32 raid_stripe_width;
	__u16 encoding;
	__u16 encoding_flags;
	__u8  def_hash_alg;
	__u8  pad_1;
	__u16 pad_2;
	__u32 feature_compat;
	__u32 feature_incompat;
	__u32 feature_ro_compat;
	__u32 set_feature_compat_mask;
	__u32 set_feature_incompat_mask;
	__u32 set_feature_ro_compat_mask;
	__u32 clear_feature_compat_mask;
	__u32 clear_feature_incompat_mask;
	__u32 clear_feature_ro_compat_mask;
	__u8  mount_opts[64];
	__u8  pad[68];
};
#define EXT4_IOC_GET_TUNE_SB_PARAM	_IOR('f', 45, struct ext4_tune_sb_params)
#endif
#ifndef EXT4_IOC_SET_TUNE_SB_PARAM
#define EXT4_IOC_SET_TUNE_SB_PARAM	_IOW('f', 46, struct ext4_tune_sb_params)
#endif

#ifndef EXT4_IOC_SHUTDOWN
#define EXT4_IOC_SHUTDOWN		_IOR('X', 125, __u32)
#endif
