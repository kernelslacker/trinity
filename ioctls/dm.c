#include <linux/ioctl.h>
#include <linux/dm-ioctl.h>

#include "shm.h"
#include "maps.h"
#include "utils.h"
#include "ioctls.h"
#include "random.h"
#include "sanitise.h"

static const struct ioctl dm_ioctls[] = {
	IOCTL(DM_VERSION),
	IOCTL(DM_REMOVE_ALL),
	IOCTL(DM_LIST_DEVICES),
	IOCTL(DM_DEV_CREATE),
	IOCTL(DM_DEV_REMOVE),
	IOCTL(DM_DEV_RENAME),
	IOCTL(DM_DEV_SUSPEND),
	IOCTL(DM_DEV_STATUS),
	IOCTL(DM_DEV_WAIT),
	IOCTL(DM_TABLE_LOAD),
	IOCTL(DM_TABLE_CLEAR),
	IOCTL(DM_TABLE_DEPS),
	IOCTL(DM_TABLE_STATUS),
	IOCTL(DM_LIST_VERSIONS),
	IOCTL(DM_TARGET_MSG),
	IOCTL(DM_DEV_SET_GEOMETRY),
};

static const char *const dm_devs[] = {
	"device-mapper",
};

static void dm_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	struct dm_ioctl *dm;

	pick_random_ioctl(grp, rec);

	rec->a3 = (unsigned long) get_writable_address(sizeof(struct dm_ioctl));
	dm = (struct dm_ioctl *) rec->a3;

	/* set a sensible version to get past the initial checks */
	dm->version[0] = DM_VERSION_MAJOR;
	dm->version[1] = DM_VERSION_MINOR;
	dm->version[2] = DM_VERSION_PATCHLEVEL;

	/* clear one of these strings to pass some kernel validation */
	if (RAND_BOOL())
		dm->name[0] = 0;
	else
		dm->uuid[0] = 0;
}

static const struct ioctl_group dm_grp_misc = {
	.devtype = DEV_MISC,
	.devs = dm_devs,
	.devs_cnt = ARRAY_SIZE(dm_devs),
	.sanitise = dm_sanitise,
	.ioctls = dm_ioctls,
	.ioctls_cnt = ARRAY_SIZE(dm_ioctls),
};

REG_IOCTL_GROUP(dm_grp_misc)

static const struct ioctl_group dm_grp_block = {
	.devtype = DEV_BLOCK,
	.devs = dm_devs,
	.devs_cnt = ARRAY_SIZE(dm_devs),
	.sanitise = dm_sanitise,
	.ioctls = dm_ioctls,
	.ioctls_cnt = ARRAY_SIZE(dm_ioctls),
};

REG_IOCTL_GROUP(dm_grp_block)
