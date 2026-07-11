
#ifdef USE_BTRFS

#include <linux/btrfs.h>

#include "utils.h"
#include "ioctls.h"

/*
 * Compile-time: BTRFS_IOC_SCAN_DEV and BTRFS_IOC_DEVICES_READY both
 * carry struct btrfs_ioctl_vol_args.  sizeof(struct) must match the
 * _IOC_SIZE encoded in the request bits, so a linux/btrfs.h refactor
 * that grows or shrinks the struct hard-fails the compile instead of
 * silently having the kernel copy_from_user() a different number of
 * bytes than we prepared.  One assert per command -- the two sides
 * can drift independently in a header refactor.
 */
IOCTL_SIZE_ASSERT(BTRFS_IOC_SCAN_DEV, struct btrfs_ioctl_vol_args);
IOCTL_SIZE_ASSERT(BTRFS_IOC_DEVICES_READY, struct btrfs_ioctl_vol_args);

static const struct ioctl btrfs_control_ioctls[] = {
	IOCTL(BTRFS_IOC_SCAN_DEV),
	IOCTL(BTRFS_IOC_DEVICES_READY),
};

static const char *const btrfs_control_devs[] = {
	"btrfs-control",
};

static const struct ioctl_group btrfs_control_grp = {
	.devtype = DEV_MISC,
	.devs = btrfs_control_devs,
	.devs_cnt = ARRAY_SIZE(btrfs_control_devs),
	.sanitise = pick_random_ioctl,
	.ioctls = btrfs_control_ioctls,
	.ioctls_cnt = ARRAY_SIZE(btrfs_control_ioctls),
};

REG_IOCTL_GROUP(btrfs_control_grp)

#endif
