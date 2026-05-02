/* /dev/vduse/{control,$NAME} VDUSE chrdev ioctl fuzzing.
 *
 * VDUSE (vDPA Device in Userspace) lets unprivileged userspace
 * implement vDPA devices.  The control chrdev creates/destroys
 * devices; each created device exposes its own per-device chrdev
 * with the IOTLB / virtqueue / config ioctls.  Both nodes live under
 * /dev/vduse/, so the fd_test below matches that prefix and lets
 * pick_random_ioctl thrash either flavour.
 *
 * The whole file is gated on USE_VDUSE so trees with kernel headers
 * predating linux/vduse.h still build.
 */

#include "config.h"

#ifdef USE_VDUSE

#include <linux/ioctl.h>
#include <linux/vduse.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

/*
 * uapi vduse.h does not export *_VALID_FLAGS masks, so hand-roll the
 * legal bit ranges from the header definitions.  Masking against these
 * keeps fuzz pressure on parsers that actually look at the field
 * instead of the kernel bouncing every call on a reserved-bit check.
 */
#define VDUSE_ACCESS_MASK	0x3UL		/* RO|WO bits, see vduse_iotlb_entry.perm */
#define VDUSE_IOVA_CAP_MASK	0x1ULL		/* VDUSE_IOVA_CAP_UMEM */

/*
 * Upper bound on the trailing config[] payload tacked onto
 * vduse_dev_config / vduse_config_data.  Picked to comfortably exceed
 * anything a real virtio device exposes while staying inside one page.
 */
#define VDUSE_FUZZ_CONFIG_MAX	1024

static int vduse_fd_test(int fd, const struct stat *st)
{
	char path[64];
	char target[64];
	ssize_t n;

	if (!S_ISCHR(st->st_mode))
		return -1;

	(void) snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
	n = readlink(path, target, sizeof(target) - 1);
	if (n < 0)
		return -1;
	target[n] = '\0';

	if (strncmp(target, "/dev/vduse/", 11) != 0)
		return -1;
	return 0;
}

static void sanitise_u64(struct syscallrecord *rec)
{
	__u64 *v;

	v = (__u64 *) get_writable_struct(sizeof(*v));
	if (!v)
		return;
	*v = rand64();
	rec->a3 = (unsigned long) v;
}

static void sanitise_u32(struct syscallrecord *rec)
{
	__u32 *v;

	v = (__u32 *) get_writable_struct(sizeof(*v));
	if (!v)
		return;
	*v = rand();
	rec->a3 = (unsigned long) v;
}

static void sanitise_dev_config(struct syscallrecord *rec)
{
	struct vduse_dev_config *c;
	size_t cfgsz, total;
	unsigned int i;

	cfgsz = rand() % VDUSE_FUZZ_CONFIG_MAX;
	total = sizeof(*c) + cfgsz;

	c = (struct vduse_dev_config *) get_writable_struct(total);
	if (!c)
		return;
	memset(c, 0, total);

	/* Random NUL-terminated name in the fixed-size name buffer. */
	for (i = 0; i < VDUSE_NAME_MAX - 1; i++)
		c->name[i] = 'a' + (rand() % 26);
	c->name[VDUSE_NAME_MAX - 1] = '\0';

	c->vendor_id = rand();
	c->device_id = rand();
	c->features = rand64();
	c->vq_num = rand() % 64;
	c->vq_align = 1U << (rand() % 13);	/* 1..4096 */
	c->config_size = cfgsz;
	for (i = 0; i < cfgsz; i++)
		c->config[i] = rand();

	rec->a3 = (unsigned long) c;
}

static void sanitise_destroy_dev(struct syscallrecord *rec)
{
	char *name;
	unsigned int i;

	name = (char *) get_writable_struct(VDUSE_NAME_MAX);
	if (!name)
		return;
	for (i = 0; i < VDUSE_NAME_MAX - 1; i++)
		name[i] = 'a' + (rand() % 26);
	name[VDUSE_NAME_MAX - 1] = '\0';
	rec->a3 = (unsigned long) name;
}

static void sanitise_iotlb_entry(struct syscallrecord *rec)
{
	struct vduse_iotlb_entry *e;
	__u64 start, span;

	e = (struct vduse_iotlb_entry *) get_writable_struct(sizeof(*e));
	if (!e)
		return;
	memset(e, 0, sizeof(*e));

	start = rand64() & 0xffffffffULL;
	span = (rand64() & 0xfffffULL) + 1;
	e->offset = rand64();
	e->start = start;
	e->last = start + span - 1;
	e->perm = (rand() & VDUSE_ACCESS_MASK);

	rec->a3 = (unsigned long) e;
}

static void sanitise_config_data(struct syscallrecord *rec)
{
	struct vduse_config_data *d;
	size_t buflen, total;
	unsigned int i;

	buflen = rand() % VDUSE_FUZZ_CONFIG_MAX;
	total = sizeof(*d) + buflen;

	d = (struct vduse_config_data *) get_writable_struct(total);
	if (!d)
		return;
	memset(d, 0, total);

	d->offset = rand() % VDUSE_FUZZ_CONFIG_MAX;
	d->length = buflen;
	for (i = 0; i < buflen; i++)
		d->buffer[i] = rand();

	rec->a3 = (unsigned long) d;
}

static void sanitise_vq_config(struct syscallrecord *rec)
{
	struct vduse_vq_config *v;

	v = (struct vduse_vq_config *) get_writable_struct(sizeof(*v));
	if (!v)
		return;
	memset(v, 0, sizeof(*v));
	v->index = rand() % 64;
	v->max_size = 1U << ((rand() % 11) + 1);	/* 2..2048 */
	rec->a3 = (unsigned long) v;
}

static void sanitise_vq_info(struct syscallrecord *rec)
{
	struct vduse_vq_info *info;

	info = (struct vduse_vq_info *) get_writable_struct(sizeof(*info));
	if (!info)
		return;
	memset(info, 0, sizeof(*info));
	info->index = rand() % 64;
	rec->a3 = (unsigned long) info;
}

static void sanitise_vq_eventfd(struct syscallrecord *rec)
{
	struct vduse_vq_eventfd *e;

	e = (struct vduse_vq_eventfd *) get_writable_struct(sizeof(*e));
	if (!e)
		return;
	e->index = rand() % 64;
	e->fd = RAND_BOOL() ? VDUSE_EVENTFD_DEASSIGN : -1;
	rec->a3 = (unsigned long) e;
}

#ifdef VDUSE_IOTLB_REG_UMEM
static void sanitise_iova_umem(struct syscallrecord *rec)
{
	struct vduse_iova_umem *u;
	unsigned int i;

	u = (struct vduse_iova_umem *) get_writable_struct(sizeof(*u));
	if (!u)
		return;
	memset(u, 0, sizeof(*u));
	u->uaddr = rand64() & ~0xfffULL;	/* page-aligned */
	u->iova = rand64() & ~0xfffULL;
	u->size = ((rand64() & 0xfffULL) + 1) << 12;
	for (i = 0; i < 3; i++)
		u->reserved[i] = 0;
	rec->a3 = (unsigned long) u;
}
#endif

#ifdef VDUSE_IOTLB_GET_INFO
static void sanitise_iova_info(struct syscallrecord *rec)
{
	struct vduse_iova_info *info;
	__u64 start, span;
	unsigned int i;

	info = (struct vduse_iova_info *) get_writable_struct(sizeof(*info));
	if (!info)
		return;
	memset(info, 0, sizeof(*info));
	start = rand64() & 0xffffffffULL;
	span = (rand64() & 0xfffffULL) + 1;
	info->start = start;
	info->last = start + span - 1;
	info->capability = rand64() & VDUSE_IOVA_CAP_MASK;
	for (i = 0; i < 3; i++)
		info->reserved[i] = 0;
	rec->a3 = (unsigned long) info;
}
#endif

static void vduse_sanitise(const struct ioctl_group *grp,
			   struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case VDUSE_GET_API_VERSION:
	case VDUSE_SET_API_VERSION:
	case VDUSE_DEV_GET_FEATURES:
		sanitise_u64(rec);
		break;

	case VDUSE_VQ_INJECT_IRQ:
		sanitise_u32(rec);
		break;

	case VDUSE_CREATE_DEV:
		sanitise_dev_config(rec);
		break;

	case VDUSE_DESTROY_DEV:
		sanitise_destroy_dev(rec);
		break;

	case VDUSE_IOTLB_GET_FD:
		sanitise_iotlb_entry(rec);
		break;

	case VDUSE_DEV_SET_CONFIG:
		sanitise_config_data(rec);
		break;

	case VDUSE_VQ_SETUP:
		sanitise_vq_config(rec);
		break;

	case VDUSE_VQ_GET_INFO:
		sanitise_vq_info(rec);
		break;

	case VDUSE_VQ_SETUP_KICKFD:
		sanitise_vq_eventfd(rec);
		break;

#ifdef VDUSE_IOTLB_REG_UMEM
	case VDUSE_IOTLB_REG_UMEM:
	case VDUSE_IOTLB_DEREG_UMEM:
		sanitise_iova_umem(rec);
		break;
#endif

#ifdef VDUSE_IOTLB_GET_INFO
	case VDUSE_IOTLB_GET_INFO:
		sanitise_iova_info(rec);
		break;
#endif

	case VDUSE_DEV_INJECT_CONFIG_IRQ:
	default:
		break;
	}
}

static const struct ioctl vduse_ioctls[] = {
	IOCTL(VDUSE_GET_API_VERSION),
	IOCTL(VDUSE_SET_API_VERSION),
	IOCTL(VDUSE_CREATE_DEV),
	IOCTL(VDUSE_DESTROY_DEV),
	IOCTL(VDUSE_IOTLB_GET_FD),
	IOCTL(VDUSE_DEV_GET_FEATURES),
	IOCTL(VDUSE_DEV_SET_CONFIG),
	IOCTL(VDUSE_DEV_INJECT_CONFIG_IRQ),
	IOCTL(VDUSE_VQ_SETUP),
	IOCTL(VDUSE_VQ_GET_INFO),
	IOCTL(VDUSE_VQ_SETUP_KICKFD),
	IOCTL(VDUSE_VQ_INJECT_IRQ),
#ifdef VDUSE_IOTLB_REG_UMEM
	IOCTL(VDUSE_IOTLB_REG_UMEM),
	IOCTL(VDUSE_IOTLB_DEREG_UMEM),
#endif
#ifdef VDUSE_IOTLB_GET_INFO
	IOCTL(VDUSE_IOTLB_GET_INFO),
#endif
};

static const struct ioctl_group vduse_grp = {
	.name = "vduse",
	.devtype = DEV_CHAR,
	.fd_test = vduse_fd_test,
	.sanitise = vduse_sanitise,
	.ioctls = vduse_ioctls,
	.ioctls_cnt = ARRAY_SIZE(vduse_ioctls),
};

REG_IOCTL_GROUP(vduse_grp)

#endif /* USE_VDUSE */
