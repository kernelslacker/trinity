#include <linux/ioctl.h>
#include <linux/fuse.h>

#include "fd.h"
#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

static void sanitise_fuse_backing_open(struct syscallrecord *rec)
{
	struct fuse_backing_map *map;

	map = (struct fuse_backing_map *) get_writable_struct(sizeof(*map));
	if (!map)
		return;
	map->fd = get_random_fd();
	map->flags = rand32();
	map->padding = rand64();
	rec->a3 = (unsigned long) map;
}

static void sanitise_fuse_backing_close(struct syscallrecord *rec)
{
	uint32_t *id;

	id = (uint32_t *) get_writable_struct(sizeof(*id));
	if (!id)
		return;
	*id = rand32();
	rec->a3 = (unsigned long) id;
}

static void fuse_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case FUSE_DEV_IOC_BACKING_OPEN:
		sanitise_fuse_backing_open(rec);
		break;
	case FUSE_DEV_IOC_BACKING_CLOSE:
		sanitise_fuse_backing_close(rec);
		break;
	default:
		break;
	}
}

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
	.sanitise = fuse_sanitise,
	.ioctls = fuse_ioctls,
	.ioctls_cnt = ARRAY_SIZE(fuse_ioctls),
};

REG_IOCTL_GROUP(fuse_grp)
