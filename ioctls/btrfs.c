#ifdef USE_BTRFS
#include <stdio.h>
#include <linux/fs.h>
#include <linux/btrfs.h>
#include "ioctls.h"
#include "shm.h"
#include "utils.h"

#ifndef BTRFS_LABEL_SIZE
#define BTRFS_LABEL_SIZE 256
#endif

#ifndef BTRFS_IOC_SET_RECEIVED_SUBVOL_32

/* If we have a 32-bit userspace and 64-bit kernel, then the UAPI
 * structures are incorrect, as the timespec structure from userspace
 * is 4 bytes too small. We define these alternatives here to teach
 * the kernel about the 32-bit struct packing.
 */
struct btrfs_ioctl_timespec_32 {
	__u64 sec;
	__u32 nsec;
} __attribute__ ((__packed__));

struct btrfs_ioctl_received_subvol_args_32 {
	char	uuid[BTRFS_UUID_SIZE];  /* in */
	__u64   stransid;		/* in */
	__u64   rtransid;		/* out */
	struct btrfs_ioctl_timespec_32 stime; /* in */
	struct btrfs_ioctl_timespec_32 rtime; /* out */
	__u64   flags;			/* in */
	__u64   reserved[16];		/* in */
};

#define BTRFS_IOC_SET_RECEIVED_SUBVOL_32 _IOWR(BTRFS_IOCTL_MAGIC, 37, \
	struct btrfs_ioctl_received_subvol_args_32)
#endif

static int btrfs_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct list_head *globallist, *node;

	globallist = shm->global_objects[OBJ_FD_TESTFILE].list;

	list_for_each(node, globallist) {
		struct object *obj;

		obj = (struct object *) node;
		if (obj->testfileobj.fd == fd)
			return 0;
	}

	return -1;
}

static const struct ioctl btrfs_ioctls[] = {
	{ .name = "FS_IOC_GETFLAGS", .request = FS_IOC_GETFLAGS, },
	{ .name = "FS_IOC_SETFLAGS", .request = FS_IOC_SETFLAGS, },
	{ .name = "FS_IOC_GETVERSION", .request = FS_IOC_GETVERSION, },
	{ .name = "FITRIM", .request = FITRIM, },

	{ .name = "BTRFS_IOC_SNAP_CREATE", .request = BTRFS_IOC_SNAP_CREATE, },
	{ .name = "BTRFS_IOC_SNAP_CREATE_V2", .request = BTRFS_IOC_SNAP_CREATE_V2, },
	{ .name = "BTRFS_IOC_SUBVOL_CREATE", .request = BTRFS_IOC_SUBVOL_CREATE, },
	{ .name = "BTRFS_IOC_SUBVOL_CREATE_V2", .request = BTRFS_IOC_SUBVOL_CREATE_V2, },
	{ .name = "BTRFS_IOC_SNAP_DESTROY", .request = BTRFS_IOC_SNAP_DESTROY, },
	{ .name = "BTRFS_IOC_SUBVOL_GETFLAGS", .request = BTRFS_IOC_SUBVOL_GETFLAGS, },
	{ .name = "BTRFS_IOC_SUBVOL_SETFLAGS", .request = BTRFS_IOC_SUBVOL_SETFLAGS, },
	{ .name = "BTRFS_IOC_DEFAULT_SUBVOL", .request = BTRFS_IOC_DEFAULT_SUBVOL, },
	{ .name = "BTRFS_IOC_DEFRAG", .request = BTRFS_IOC_DEFRAG, },
	{ .name = "BTRFS_IOC_DEFRAG_RANGE", .request = BTRFS_IOC_DEFRAG_RANGE, },
	{ .name = "BTRFS_IOC_RESIZE", .request = BTRFS_IOC_RESIZE, },
	{ .name = "BTRFS_IOC_ADD_DEV", .request = BTRFS_IOC_ADD_DEV, },
	{ .name = "BTRFS_IOC_RM_DEV", .request = BTRFS_IOC_RM_DEV, },
	{ .name = "BTRFS_IOC_FS_INFO", .request = BTRFS_IOC_FS_INFO, },
	{ .name = "BTRFS_IOC_DEV_INFO", .request = BTRFS_IOC_DEV_INFO, },
	{ .name = "BTRFS_IOC_BALANCE", .request = BTRFS_IOC_BALANCE, },
	{ .name = "BTRFS_IOC_TRANS_START", .request = BTRFS_IOC_TRANS_START, },
	{ .name = "BTRFS_IOC_TRANS_END", .request = BTRFS_IOC_TRANS_END, },
	{ .name = "BTRFS_IOC_TREE_SEARCH", .request = BTRFS_IOC_TREE_SEARCH, },
	{ .name = "BTRFS_IOC_TREE_SEARCH_V2", .request = BTRFS_IOC_TREE_SEARCH_V2, },
	{ .name = "BTRFS_IOC_INO_LOOKUP", .request = BTRFS_IOC_INO_LOOKUP, },
	{ .name = "BTRFS_IOC_INO_PATHS", .request = BTRFS_IOC_INO_PATHS, },
	{ .name = "BTRFS_IOC_LOGICAL_INO", .request = BTRFS_IOC_LOGICAL_INO, },
	{ .name = "BTRFS_IOC_SPACE_INFO", .request = BTRFS_IOC_SPACE_INFO, },
	{ .name = "BTRFS_IOC_SYNC", .request = BTRFS_IOC_SYNC, },
	{ .name = "BTRFS_IOC_START_SYNC", .request = BTRFS_IOC_START_SYNC, },
	{ .name = "BTRFS_IOC_WAIT_SYNC", .request = BTRFS_IOC_WAIT_SYNC, },
	{ .name = "BTRFS_IOC_SCRUB", .request = BTRFS_IOC_SCRUB, },
	{ .name = "BTRFS_IOC_SCRUB_CANCEL", .request = BTRFS_IOC_SCRUB_CANCEL, },
	{ .name = "BTRFS_IOC_SCRUB_PROGRESS", .request = BTRFS_IOC_SCRUB_PROGRESS, },
	{ .name = "BTRFS_IOC_BALANCE_V2", .request = BTRFS_IOC_BALANCE_V2, },
	{ .name = "BTRFS_IOC_BALANCE_CTL", .request = BTRFS_IOC_BALANCE_CTL, },
	{ .name = "BTRFS_IOC_BALANCE_PROGRESS", .request = BTRFS_IOC_BALANCE_PROGRESS, },
	{ .name = "BTRFS_IOC_SET_RECEIVED_SUBVOL", .request = BTRFS_IOC_SET_RECEIVED_SUBVOL, },
	{ .name = "BTRFS_IOC_SET_RECEIVED_SUBVOL_32", .request = BTRFS_IOC_SET_RECEIVED_SUBVOL_32, },
	{ .name = "BTRFS_IOC_SEND", .request = BTRFS_IOC_SEND, },
	{ .name = "BTRFS_IOC_GET_DEV_STATS", .request = BTRFS_IOC_GET_DEV_STATS, },
	{ .name = "BTRFS_IOC_QUOTA_CTL", .request = BTRFS_IOC_QUOTA_CTL, },
	{ .name = "BTRFS_IOC_QGROUP_ASSIGN", .request = BTRFS_IOC_QGROUP_ASSIGN, },
	{ .name = "BTRFS_IOC_QGROUP_CREATE", .request = BTRFS_IOC_QGROUP_CREATE, },
	{ .name = "BTRFS_IOC_QGROUP_LIMIT", .request = BTRFS_IOC_QGROUP_LIMIT, },
	{ .name = "BTRFS_IOC_QUOTA_RESCAN", .request = BTRFS_IOC_QUOTA_RESCAN, },
	{ .name = "BTRFS_IOC_QUOTA_RESCAN_STATUS", .request = BTRFS_IOC_QUOTA_RESCAN_STATUS, },
	{ .name = "BTRFS_IOC_QUOTA_RESCAN_WAIT", .request = BTRFS_IOC_QUOTA_RESCAN_WAIT, },
	{ .name = "BTRFS_IOC_DEV_REPLACE", .request = BTRFS_IOC_DEV_REPLACE, },
	{ .name = "BTRFS_IOC_GET_FSLABEL", .request = BTRFS_IOC_GET_FSLABEL, },
	{ .name = "BTRFS_IOC_SET_FSLABEL", .request = BTRFS_IOC_SET_FSLABEL, },
	{ .name = "BTRFS_IOC_GET_SUPPORTED_FEATURES", .request = BTRFS_IOC_GET_SUPPORTED_FEATURES, },
	{ .name = "BTRFS_IOC_GET_FEATURES", .request = BTRFS_IOC_GET_FEATURES, },
	{ .name = "BTRFS_IOC_SET_FEATURES", .request = BTRFS_IOC_SET_FEATURES, },
};

static const struct ioctl_group btrfs_grp = {
	.name = "btrfs",
	.fd_test = btrfs_fd_test,
	.sanitise = pick_random_ioctl,
	.ioctls = btrfs_ioctls,
	.ioctls_cnt = ARRAY_SIZE(btrfs_ioctls),
};

REG_IOCTL_GROUP(btrfs_grp)
#endif /* USE_BTRFS */
