#ifdef USE_NVME
#include <linux/ioctl.h>
#include <linux/nvme_ioctl.h>

#include "compat.h"
#include "utils.h"
#include "ioctls.h"

static const struct ioctl nvme_ioctls[] = {
	IOCTL(NVME_IOCTL_ID),
	IOCTL(NVME_IOCTL_ADMIN_CMD),
	IOCTL(NVME_IOCTL_SUBMIT_IO),
	IOCTL(NVME_IOCTL_IO_CMD),
	IOCTL(NVME_IOCTL_RESET),
};

static const char *const nvme_devs[] = {
	"nvme",
};

static const struct ioctl_group nvme_grp_misc = {
	.devtype = DEV_CHAR,
	.devs = nvme_devs,
	.devs_cnt = ARRAY_SIZE(nvme_devs),
	.sanitise = pick_random_ioctl,
	.ioctls = nvme_ioctls,
	.ioctls_cnt = ARRAY_SIZE(nvme_ioctls),
};

REG_IOCTL_GROUP(nvme_grp_misc)

static const struct ioctl_group nvme_grp_block = {
	.devtype = DEV_BLOCK,
	.devs = nvme_devs,
	.devs_cnt = ARRAY_SIZE(nvme_devs),
	.sanitise = pick_random_ioctl,
	.ioctls = nvme_ioctls,
	.ioctls_cnt = ARRAY_SIZE(nvme_ioctls),
};

REG_IOCTL_GROUP(nvme_grp_block);
#endif
