#include <linux/ioctl.h>
#include <linux/dm-ioctl.h>

#include "shm.h"
#include "maps.h"
#include "utils.h"
#include "ioctls.h"
#include "random.h"
#include "sanitise.h"

/*
 * Compile-time: every DM_* command carries the same fixed-shape
 * struct dm_ioctl header (a trailing data area flexes past
 * sizeof(struct) at runtime via ->data_start / ->data_size, but
 * the header itself is what _IOC_SIZE encodes and what the
 * sanitiser fills).  Pin sizeof(struct dm_ioctl) against a
 * representative _IOC_SIZE so a <linux/dm-ioctl.h> layout change
 * that grows or shrinks the header (a wider event_nr, an
 * extended name[]/uuid[] pair) hard-fails the compile rather
 * than silently letting the kernel copy_from_user() a different
 * number of bytes than the sanitiser prepared.  DM_VERSION stands
 * in for all DM_* commands -- the uapi wires every command to
 * struct dm_ioctl, so a single anchor is enough.
 */
IOCTL_SIZE_ASSERT(DM_VERSION, struct dm_ioctl);

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
#ifdef DM_DEV_ARM_POLL
	IOCTL(DM_DEV_ARM_POLL),
#endif
#ifdef DM_GET_TARGET_VERSION
	IOCTL(DM_GET_TARGET_VERSION),
#endif
#ifdef DM_MPATH_PROBE_PATHS
	IOCTL(DM_MPATH_PROBE_PATHS),
#endif
};

static const char *const dm_devs[] = {
	"device-mapper",
};

static void dm_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	struct dm_ioctl *dm;

	pick_random_ioctl(grp, rec);

	rec->a3 = (unsigned long) get_writable_address(sizeof(struct dm_ioctl));
	if (rec->a3 == 0)
		return;
	dm = (struct dm_ioctl *) rec->a3;

	/*
	 * get_writable_address() hands out un-zeroed bump-pool memory that
	 * may still hold a prior syscall's typed struct (valid user VA
	 * pointers included).  Zero it so copy_from_user never reads stale
	 * bytes as data_size / target_count / flags.  This also empties
	 * name[] and uuid[], which passes the kernel's "not both set"
	 * validation without a separate clear step.
	 */
	memset(dm, 0, sizeof(*dm));

	/* set a sensible version to get past the initial checks */
	dm->version[0] = DM_VERSION_MAJOR;
	dm->version[1] = DM_VERSION_MINOR;
	dm->version[2] = DM_VERSION_PATCHLEVEL;
	dm->data_size = sizeof(*dm);
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
