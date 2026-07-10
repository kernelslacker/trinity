
#ifdef USE_IOMMUFD
#include <string.h>
#include <linux/iommufd.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "syscall.h"
#include "utils.h"

static const struct ioctl iommufd_ioctls[] = {
	IOCTL(IOMMU_DESTROY),
	IOCTL(IOMMU_IOAS_ALLOC),
	IOCTL(IOMMU_IOAS_IOVA_RANGES),
	IOCTL(IOMMU_IOAS_ALLOW_IOVAS),
	IOCTL(IOMMU_IOAS_MAP),
	IOCTL(IOMMU_IOAS_COPY),
	IOCTL(IOMMU_IOAS_UNMAP),
	IOCTL(IOMMU_OPTION),
	IOCTL(IOMMU_VFIO_IOAS),
	IOCTL(IOMMU_HWPT_ALLOC),
	IOCTL(IOMMU_GET_HW_INFO),
	IOCTL(IOMMU_HWPT_SET_DIRTY_TRACKING),
	IOCTL(IOMMU_HWPT_GET_DIRTY_BITMAP),
	IOCTL(IOMMU_HWPT_INVALIDATE),
#ifdef IOMMU_FAULT_QUEUE_ALLOC
	IOCTL(IOMMU_FAULT_QUEUE_ALLOC),
#endif
#ifdef IOMMU_IOAS_MAP_FILE
	IOCTL(IOMMU_IOAS_MAP_FILE),
#endif
#ifdef IOMMU_VIOMMU_ALLOC
	IOCTL(IOMMU_VIOMMU_ALLOC),
#endif
#ifdef IOMMU_VDEVICE_ALLOC
	IOCTL(IOMMU_VDEVICE_ALLOC),
#endif
#ifdef IOMMU_IOAS_CHANGE_PROCESS
	IOCTL(IOMMU_IOAS_CHANGE_PROCESS),
#endif
#ifdef IOMMU_VEVENTQ_ALLOC
	IOCTL(IOMMU_VEVENTQ_ALLOC),
#endif
#ifdef IOMMU_HW_QUEUE_ALLOC
	IOCTL(IOMMU_HW_QUEUE_ALLOC),
#endif
};

/*
 * Per-IOMMUFD ioctl struct-arg seeding.  Mirrors the kvm_vm_sanitise() pattern:
 * delegate ioctl selection to pick_random_ioctl(), then override rec->a3 for
 * the commands whose argument is a struct.  Every IOMMUFD request is declared
 * with _IO() (size/direction are carried in-band by the struct's size field),
 * so the generic arg-shape picker in ioctls.c hands the kernel a random-shaped
 * buffer and the map/unmap/iova-ranges paths bounce on the size/reserved
 * checks before reaching the IOAS machinery.  IOMMUFD is on the efault_cache
 * opt-out list, so no probe leak is introduced here -- this sanitiser
 * replaces the random path entirely.
 */
#define IOMMUFD_FUZZ_PAGE_SIZE		0x1000UL
#define IOMMUFD_FUZZ_IOVA_LIMIT		(1UL << 40)
#define IOMMUFD_FUZZ_MAX_ORDER		6	/* 4K .. 256K */
#define IOMMUFD_FUZZ_MAX_ID		64
#define IOMMUFD_FUZZ_MAX_RANGES		16

static void sanitise_iommufd_destroy(struct syscallrecord *rec)
{
	struct iommu_destroy *d;

	d = get_writable_address(sizeof(*d));
	if (d == NULL)
		return;

	memset(d, 0, sizeof(*d));
	d->size = sizeof(*d);
	d->id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);

	rec->a3 = (unsigned long)d;
}

static void sanitise_iommufd_ioas_alloc(struct syscallrecord *rec)
{
	struct iommu_ioas_alloc *a;

	a = get_writable_address(sizeof(*a));
	if (a == NULL)
		return;

	memset(a, 0, sizeof(*a));
	a->size = sizeof(*a);

	rec->a3 = (unsigned long)a;
}

static void sanitise_iommufd_ioas_map(struct syscallrecord *rec)
{
	struct iommu_ioas_map *m;
	void *ua;
	__u64 length;

	m = get_writable_address(sizeof(*m));
	if (m == NULL)
		return;

	length = IOMMUFD_FUZZ_PAGE_SIZE
	       << rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ORDER + 1);

	ua = get_writable_address(length);
	if (ua == NULL)
		return;

	memset(m, 0, sizeof(*m));
	m->size = sizeof(*m);
	m->flags = IOMMU_IOAS_MAP_READABLE | IOMMU_IOAS_MAP_WRITEABLE;
	if (ONE_IN(4))
		m->flags |= IOMMU_IOAS_MAP_FIXED_IOVA;
	m->ioas_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	m->user_va = (__u64)(unsigned long)ua;
	m->length = length;
	m->iova = rnd_modulo_u64(IOMMUFD_FUZZ_IOVA_LIMIT)
		& ~(IOMMUFD_FUZZ_PAGE_SIZE - 1);

	rec->a3 = (unsigned long)m;
}

static void sanitise_iommufd_ioas_unmap(struct syscallrecord *rec)
{
	struct iommu_ioas_unmap *u;
	__u64 length;

	u = get_writable_address(sizeof(*u));
	if (u == NULL)
		return;

	length = IOMMUFD_FUZZ_PAGE_SIZE
	       << rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ORDER + 1);

	memset(u, 0, sizeof(*u));
	u->size = sizeof(*u);
	u->ioas_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	u->iova = rnd_modulo_u64(IOMMUFD_FUZZ_IOVA_LIMIT)
		& ~(IOMMUFD_FUZZ_PAGE_SIZE - 1);
	u->length = length;

	rec->a3 = (unsigned long)u;
}

static void sanitise_iommufd_ioas_iova_ranges(struct syscallrecord *rec)
{
	struct iommu_ioas_iova_ranges *r;
	void *ranges;
	__u32 num_iovas;
	unsigned long buf_sz;

	r = get_writable_address(sizeof(*r));
	if (r == NULL)
		return;

	num_iovas = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_RANGES + 1);
	buf_sz = (unsigned long)num_iovas * sizeof(struct iommu_iova_range);
	if (buf_sz == 0)
		buf_sz = sizeof(struct iommu_iova_range);

	ranges = get_writable_address(buf_sz);
	if (ranges == NULL)
		return;

	memset(r, 0, sizeof(*r));
	r->size = sizeof(*r);
	r->ioas_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	r->num_iovas = num_iovas;
	r->allowed_iovas = (__u64)(unsigned long)ranges;

	rec->a3 = (unsigned long)r;
}

static void iommufd_sanitise(const struct ioctl_group *grp,
			     struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case IOMMU_DESTROY:
		sanitise_iommufd_destroy(rec);
		break;
	case IOMMU_IOAS_ALLOC:
		sanitise_iommufd_ioas_alloc(rec);
		break;
	case IOMMU_IOAS_MAP:
		sanitise_iommufd_ioas_map(rec);
		break;
	case IOMMU_IOAS_UNMAP:
		sanitise_iommufd_ioas_unmap(rec);
		break;
	case IOMMU_IOAS_IOVA_RANGES:
		sanitise_iommufd_ioas_iova_ranges(rec);
		break;
	default:
		break;
	}
}

static const char *const iommufd_devs[] = {
	"iommu",
};

static const struct ioctl_group iommufd_grp = {
	.devtype = DEV_MISC,
	.devs = iommufd_devs,
	.devs_cnt = ARRAY_SIZE(iommufd_devs),
	.sanitise = iommufd_sanitise,
	.ioctls = iommufd_ioctls,
	.ioctls_cnt = ARRAY_SIZE(iommufd_ioctls),
};

REG_IOCTL_GROUP(iommufd_grp)
#endif
