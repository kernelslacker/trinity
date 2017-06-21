#include <stdio.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/blktrace_api.h>
#ifdef USE_FSMAP
#include <linux/fsmap.h>
#endif
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
		if (obj->pipeobj.fd == fd)
			return 0;
	}

	globallist = shm->global_objects[OBJ_FD_FILE].list;
	list_for_each(node, globallist) {
		obj = (struct object *) node;
		if (obj->fileobj.fd == fd)
			return 0;
	}

	globallist = shm->global_objects[OBJ_FD_TESTFILE].list;
	list_for_each(node, globallist) {
		obj = (struct object *) node;
		if (obj->testfileobj.fd == fd)
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
#ifdef BLKROSET
	{ .name = "BLKROSET", .request = BLKROSET, },
#endif
#ifdef BLKROGET
	{ .name = "BLKROGET", .request = BLKROGET, },
#endif
#ifdef BLKRRPART
	{ .name = "BLKRRPART", .request = BLKRRPART, },
#endif
#ifdef BLKGETSIZE
	{ .name = "BLKGETSIZE", .request = BLKGETSIZE, },
#endif
#ifdef BLKFLSBUF
	{ .name = "BLKFLSBUF", .request = BLKFLSBUF, },
#endif
#ifdef BLKRASET
	{ .name = "BLKRASET", .request = BLKRASET, },
#endif
#ifdef BLKRAGET
	{ .name = "BLKRAGET", .request = BLKRAGET, },
#endif
#ifdef BLKFRASET
	{ .name = "BLKFRASET", .request = BLKFRASET, },
#endif
#ifdef BLKFRAGET
	{ .name = "BLKFRAGET", .request = BLKFRAGET, },
#endif
#ifdef BLKSECTSET
	{ .name = "BLKSECTSET", .request = BLKSECTSET, },
#endif
#ifdef BLKSECTGET
	{ .name = "BLKSECTGET", .request = BLKSECTGET, },
#endif
#ifdef BLKSSZGET
	{ .name = "BLKSSZGET", .request = BLKSSZGET, },
#endif
#ifdef BLKBSZGET
	{ .name = "BLKBSZGET", .request = BLKBSZGET, },
#endif
#ifdef BLKBSZSET
	{ .name = "BLKBSZSET", .request = BLKBSZSET, },
#endif
#ifdef BLKGETSIZE64
	{ .name = "BLKGETSIZE64", .request = BLKGETSIZE64, },
#endif
#ifdef BLKTRACESETUP
	{ .name = "BLKTRACESETUP", .request = BLKTRACESETUP, },
#endif
#ifdef BLKTRACESTART
	{ .name = "BLKTRACESTART", .request = BLKTRACESTART, },
#endif
#ifdef BLKTRACESTOP
	{ .name = "BLKTRACESTOP", .request = BLKTRACESTOP, },
#endif
#ifdef BLKTRACETEARDOWN
	{ .name = "BLKTRACETEARDOWN", .request = BLKTRACETEARDOWN, },
#endif
#ifdef BLKDISCARD
	{ .name = "BLKDISCARD", .request = BLKDISCARD, },
#endif
#ifdef BLKIOMIN
	{ .name = "BLKIOMIN", .request = BLKIOMIN, },
#endif
#ifdef BLKIOOPT
	{ .name = "BLKIOOPT", .request = BLKIOOPT, },
#endif
#ifdef BLKALIGNOFF
	{ .name = "BLKALIGNOFF", .request = BLKALIGNOFF, },
#endif
#ifdef BLKPBSZGET
	{ .name = "BLKPBSZGET", .request = BLKPBSZGET, },
#endif
#ifdef BLKDISCARDZEROES
	{ .name = "BLKDISCARDZEROES", .request = BLKDISCARDZEROES, },
#endif
#ifdef BLKSECDISCARD
	{ .name = "BLKSECDISCARD", .request = BLKSECDISCARD, },
#endif
#ifdef BLKROTATIONAL
	{ .name = "BLKROTATIONAL", .request = BLKROTATIONAL, },
#endif
#ifdef BLKZEROOUT
	{ .name = "BLKZEROOUT", .request = BLKZEROOUT, },
#endif
#ifdef FITRIM
	{ .name = "FITRIM", .request = FITRIM, },
#endif
#ifdef FS_IOC_GETFLAGS
	{ .name = "FS_IOC_GETFLAGS", .request = FS_IOC_GETFLAGS, },
#endif
#ifdef FS_IOC_SETFLAGS
	{ .name = "FS_IOC_SETFLAGS", .request = FS_IOC_SETFLAGS, },
#endif
#ifdef FS_IOC_GETVERSION
	{ .name = "FS_IOC_GETVERSION", .request = FS_IOC_GETVERSION, },
#endif
#ifdef FS_IOC_SETVERSION
	{ .name = "FS_IOC_SETVERSION", .request = FS_IOC_SETVERSION, },
#endif
#ifdef FS_IOC32_GETFLAGS
	{ .name = "FS_IOC32_GETFLAGS", .request = FS_IOC32_GETFLAGS, },
#endif
#ifdef FS_IOC32_SETFLAGS
	{ .name = "FS_IOC32_SETFLAGS", .request = FS_IOC32_SETFLAGS, },
#endif
#ifdef FS_IOC32_GETVERSION
	{ .name = "FS_IOC32_GETVERSION", .request = FS_IOC32_GETVERSION, },
#endif
#ifdef FS_IOC32_SETVERSION
	{ .name = "FS_IOC32_SETVERSION", .request = FS_IOC32_SETVERSION, },
#endif
#ifdef FS_IOC_FSGETXATTR
	{ .name = "FS_IOC_FSGETXATTR", .request = FS_IOC_FSGETXATTR, },
#endif
#ifdef FS_IOC_FSSETXATTR
	{ .name = "FS_IOC_FSSETXATTR", .request = FS_IOC_FSSETXATTR, },
#endif
#ifdef FS_IOC_SET_ENCRYPTION_POLICY
	{ .name = "FS_IOC_SET_ENCRYPTION_POLICY", .request = FS_IOC_SET_ENCRYPTION_POLICY, },
#endif
#ifdef FS_IOC_GET_ENCRYPTION_PWSALT
	{ .name = "FS_IOC_GET_ENCRYPTION_PWSALT", .request = FS_IOC_GET_ENCRYPTION_PWSALT, },
#endif
#ifdef FS_IOC_GET_ENCRYPTION_POLICY
	{ .name = "FS_IOC_GET_ENCRYPTION_POLICY", .request = FS_IOC_GET_ENCRYPTION_POLICY, },
#endif
#ifdef FS_IOC_GETFSMAP
	{ .name = "FS_IOC_GETFSMAP", .request = FS_IOC_GETFSMAP, },
#endif
};

static const struct ioctl_group vfs_grp = {
	.name = "vfs",
	.fd_test = vfs_fd_test,
	.sanitise = pick_random_ioctl,
	.ioctls = vfs_ioctls,
	.ioctls_cnt = ARRAY_SIZE(vfs_ioctls),
};

REG_IOCTL_GROUP(vfs_grp)
