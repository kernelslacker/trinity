#include <linux/ioctl.h>
#include <linux/fuse.h>

#include "ioctls.h"
#include "utils.h"

static const struct ioctl fuse_ioctls[] = {
	IOCTL(FUSE_DEV_IOC_CLONE),
	IOCTL(FUSE_DEV_IOC_BACKING_OPEN),
	IOCTL(FUSE_DEV_IOC_BACKING_CLOSE),
#ifdef FUSE_DEV_IOC_SYNC_INIT
	IOCTL(FUSE_DEV_IOC_SYNC_INIT),
#endif
};

static const char *const fuse_devs[] = {
	"fuse",
};

static const struct ioctl_group fuse_grp = {
	.devtype = DEV_MISC,
	.devs = fuse_devs,
	.devs_cnt = ARRAY_SIZE(fuse_devs),
	.sanitise = pick_random_ioctl,
	.ioctls = fuse_ioctls,
	.ioctls_cnt = ARRAY_SIZE(fuse_ioctls),
};

REG_IOCTL_GROUP(fuse_grp)
