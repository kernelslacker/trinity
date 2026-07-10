#include <linux/ioctl.h>
#include <linux/fuse.h>

#include "fd.h"
#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

/*
 * Compile-time: FUSE_DEV_IOC_BACKING_OPEN is the only fixed-shape
 * struct command this file fills.  Pin sizeof(struct
 * fuse_backing_map) against its _IOC_SIZE so a <linux/fuse.h>
 * change that grows or shrinks the struct (an extra flags word,
 * a wider padding field) hard-fails the compile rather than
 * silently having the kernel copy_from_user() a different number
 * of bytes than the sanitiser prepared.
 *
 * FUSE_DEV_IOC_CLONE and FUSE_DEV_IOC_BACKING_CLOSE both take a
 * bare uint32_t; FUSE_DEV_IOC_SYNC_INIT (when the uapi defines it)
 * is _IO() with no arg.  Asserting sizeof(struct) against a
 * scalar or a zero _IOC_SIZE would be the wrong shape of check.
 */
_Static_assert(sizeof(struct fuse_backing_map) ==
	       _IOC_SIZE(FUSE_DEV_IOC_BACKING_OPEN),
	       "fuse_backing_map size vs _IOC_SIZE mismatch");

static void sanitise_fuse_clone(struct syscallrecord *rec)
{
	uint32_t *fd;

	fd = (uint32_t *) get_writable_struct(sizeof(*fd));
	if (!fd)
		return;
	memset(fd, 0, sizeof(*fd));
	*fd = get_random_fd();
	rec->a3 = (unsigned long) fd;
}

static void sanitise_fuse_backing_open(struct syscallrecord *rec)
{
	struct fuse_backing_map *map;

	map = (struct fuse_backing_map *) get_writable_struct(sizeof(*map));
	if (!map)
		return;
	memset(map, 0, sizeof(*map));
	map->fd = get_random_fd();
	map->flags = ONE_IN(16) ? rand32() : 0;
	map->padding = ONE_IN(16) ? rand64() : 0;
	rec->a3 = (unsigned long) map;
}

static void sanitise_fuse_backing_close(struct syscallrecord *rec)
{
	uint32_t *id;

	id = (uint32_t *) get_writable_struct(sizeof(*id));
	if (!id)
		return;
	memset(id, 0, sizeof(*id));
	*id = rand32();
	rec->a3 = (unsigned long) id;
}

static void fuse_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case FUSE_DEV_IOC_CLONE:
		sanitise_fuse_clone(rec);
		break;
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
