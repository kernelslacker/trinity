#include <linux/ioctl.h>
#include <linux/fuse.h>

#include "fd.h"
#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

/*
 * Compile-time: pin each fixed-shape command's payload against its
 * _IOC_SIZE so a <linux/fuse.h> change that grows or shrinks the
 * type (an extra flags word, a wider padding field, a scalar
 * widened to 64 bits) hard-fails the compile rather than silently
 * having the kernel copy_from_user() a different number of bytes
 * than the sanitiser prepared.
 *
 * FUSE_DEV_IOC_SYNC_INIT (when the uapi defines it) is _IO() with
 * no arg, so there is nothing to size-check.
 */
IOCTL_SIZE_ASSERT(FUSE_DEV_IOC_CLONE, uint32_t);
IOCTL_SIZE_ASSERT(FUSE_DEV_IOC_BACKING_OPEN, struct fuse_backing_map);
IOCTL_SIZE_ASSERT(FUSE_DEV_IOC_BACKING_CLOSE, uint32_t);
#ifdef FUSE_DEV_IOC_BACKING_CREATE
IOCTL_SIZE_ASSERT(FUSE_DEV_IOC_BACKING_CREATE, struct fuse_backing_create_in);
#endif

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

#ifdef FUSE_DEV_IOC_BACKING_CREATE
/*
 * BACKING_CREATE (7.4) registers the backing file under an id the server
 * picks, on a connection that negotiated 64-bit ids, and
 * fuse_backing_open_64() refuses padding, spare words or an id of 0.
 */
static void sanitise_fuse_backing_create(struct syscallrecord *rec)
{
	struct fuse_backing_create_in *map;

	map = (struct fuse_backing_create_in *) get_writable_struct(sizeof(*map));
	if (!map)
		return;
	memset(map, 0, sizeof(*map));
	map->fd = get_random_fd();
	map->backing_id = ONE_IN(16) ? 0 : 1 + rnd_modulo_u32(64);
	map->padding = ONE_IN(16) ? rand32() : 0;
	map->spare[0] = ONE_IN(16) ? rand64() : 0;
	rec->a3 = (unsigned long) map;
}
#endif

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
#ifdef FUSE_DEV_IOC_BACKING_CREATE
	case FUSE_DEV_IOC_BACKING_CREATE:
		sanitise_fuse_backing_create(rec);
		break;
#endif
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
#ifdef FUSE_DEV_IOC_BACKING_CREATE
	IOCTL(FUSE_DEV_IOC_BACKING_CREATE),
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
