#include <stdio.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <asm/ioctls.h>
#include "ioctls.h"
#include "net.h"
#include "shm.h"
#include "utils.h"

static int vfs_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct list_head *globallist, *node;
	struct object *obj;

	globallist = shm->global_objects[OBJ_FD_PIPE].list;
	list_for_each(node, globallist) {
		obj = (struct object *) node;
		if (obj->pipefd == fd)
			return 0;
	}

	globallist = shm->global_objects[OBJ_FD_FILE].list;
	list_for_each(node, globallist) {
		obj = (struct object *) node;
		if (obj->filefd == fd)
			return 0;
	}

	globallist = shm->global_objects[OBJ_FD_TESTFILE].list;
	list_for_each(node, globallist) {
		obj = (struct object *) node;
		if (obj->testfilefd == fd)
			return 0;
	}

	/* TODO: There may be other fd types we can perform vfs ioctls on */

	return -1;
}

#ifndef FICLONE
#define FICLONE		_IOW(0x94, 9, int)
#endif

#ifndef FICLONERANGE
struct file_clone_range {
	__s64 src_fd;
	__u64 src_offset;
	__u64 src_length;
	__u64 dest_offset;
};
#define FICLONERANGE	_IOW(0x94, 13, struct file_clone_range)
#endif

#ifndef FIDEDUPERANGE
/* from struct btrfs_ioctl_file_extent_same_info */
struct file_dedupe_range_info {
	__s64 dest_fd;          /* in - destination file */
	__u64 dest_offset;      /* in - start of extent in destination */
	__u64 bytes_deduped;    /* out - total # of bytes we were able
				 * to dedupe from this file. */
	/* status of this dedupe operation:
	 * < 0 for error
	 * == FILE_DEDUPE_RANGE_SAME if dedupe succeeds
	 * == FILE_DEDUPE_RANGE_DIFFERS if data differs
	 */
	__s32 status;           /* out - see above description */
	__u32 reserved;         /* must be zero */
};

/* from struct btrfs_ioctl_file_extent_same_args */
struct file_dedupe_range {
	__u64 src_offset;       /* in - start of extent in source */
	__u64 src_length;       /* in - length of extent */
	__u16 dest_count;       /* in - total elements in info array */
	__u16 reserved1;        /* must be zero */
	__u32 reserved2;        /* must be zero */
	struct file_dedupe_range_info info[0];
};
#define FIDEDUPERANGE	_IOWR(0x94, 54, struct file_dedupe_range)
#endif

#ifndef FS_IOC_RESVSP
struct space_resv {
	__s16 l_type;
	__s16 l_whence;
	__s64 l_start;
	__s64 l_len;          /* len == 0 means until end of file */
	__s32 l_sysid;
	__u32 l_pid;
	__s32 l_pad[4];       /* reserved area */
};
#define FS_IOC_RESVSP		_IOW('X', 40, struct space_resv)
#endif
#ifndef FS_IOC_RESVSP64
#define FS_IOC_RESVSP64		_IOW('X', 42, struct space_resv)
#endif

static const struct ioctl vfs_ioctls[] = {
	{ .name = "FIOCLEX", .request = FIOCLEX, },
	{ .name = "FIONCLEX", .request = FIONCLEX, },
	{ .name = "FIONBIO", .request = FIONBIO, },
	{ .name = "FIOASYNC", .request = FIOASYNC, },
	{ .name = "FIOQSIZE", .request = FIOQSIZE, },
	{ .name = "FIFREEZE", .request = FIFREEZE, },
	{ .name = "FITHAW", .request = FITHAW, },
	{ .name = "FS_IOC_FIEMAP", .request = FS_IOC_FIEMAP, },
	{ .name = "FIGETBSZ", .request = FIGETBSZ, },
	{ .name = "FICLONE", .request = FICLONE, },
	{ .name = "FICLONERANGE", .request = FICLONERANGE, },
	{ .name = "FIDEDUPERANGE", .request = FIDEDUPERANGE, },
	{ .name = "FIBMAP", .request = FIBMAP, },
	{ .name = "FIONREAD", .request = FIONREAD, },
	{ .name = "FS_IOC_RESVSP", .request = FS_IOC_RESVSP, },
	{ .name = "FS_IOC_RESVSP64", .request = FS_IOC_RESVSP64, },
};

static const struct ioctl_group vfs_grp = {
	.name = "vfs",
	.fd_test = vfs_fd_test,
	.sanitise = pick_random_ioctl,
	.ioctls = vfs_ioctls,
	.ioctls_cnt = ARRAY_SIZE(vfs_ioctls),
};

REG_IOCTL_GROUP(vfs_grp)
