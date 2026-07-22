
#ifdef USE_VFIO
#include <string.h>
#include <linux/vfio.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "syscall.h"
#include "utils.h"

static const struct ioctl vfio_ioctls[] = {
	IOCTL(VFIO_GET_API_VERSION),
	IOCTL(VFIO_CHECK_EXTENSION),
	IOCTL(VFIO_SET_IOMMU),
	IOCTL(VFIO_GROUP_GET_STATUS),
	IOCTL(VFIO_GROUP_SET_CONTAINER),
	IOCTL(VFIO_GROUP_UNSET_CONTAINER),
	IOCTL(VFIO_GROUP_GET_DEVICE_FD),
	IOCTL(VFIO_DEVICE_GET_INFO),
	IOCTL(VFIO_DEVICE_GET_REGION_INFO),
	IOCTL(VFIO_DEVICE_GET_IRQ_INFO),
	IOCTL(VFIO_DEVICE_SET_IRQS),
	IOCTL(VFIO_DEVICE_RESET),
	IOCTL(VFIO_IOMMU_GET_INFO),
	IOCTL(VFIO_IOMMU_MAP_DMA),
	IOCTL(VFIO_IOMMU_UNMAP_DMA),
#ifdef VFIO_DEVICE_GET_PCI_HOT_RESET_INFO
	IOCTL(VFIO_DEVICE_GET_PCI_HOT_RESET_INFO),
#endif
#ifdef VFIO_DEVICE_PCI_HOT_RESET
	IOCTL(VFIO_DEVICE_PCI_HOT_RESET),
#endif
#ifdef VFIO_DEVICE_QUERY_GFX_PLANE
	IOCTL(VFIO_DEVICE_QUERY_GFX_PLANE),
#endif
#ifdef VFIO_DEVICE_GET_GFX_DMABUF
	IOCTL(VFIO_DEVICE_GET_GFX_DMABUF),
#endif
#ifdef VFIO_DEVICE_IOEVENTFD
	IOCTL(VFIO_DEVICE_IOEVENTFD),
#endif
#ifdef VFIO_DEVICE_FEATURE
	IOCTL(VFIO_DEVICE_FEATURE),
#endif
#ifdef VFIO_IOMMU_DIRTY_PAGES
	IOCTL(VFIO_IOMMU_DIRTY_PAGES),
#endif
#ifdef VFIO_DEVICE_BIND_IOMMUFD
	IOCTL(VFIO_DEVICE_BIND_IOMMUFD),
#endif
#ifdef VFIO_DEVICE_ATTACH_IOMMUFD_PT
	IOCTL(VFIO_DEVICE_ATTACH_IOMMUFD_PT),
#endif
#ifdef VFIO_DEVICE_DETACH_IOMMUFD_PT
	IOCTL(VFIO_DEVICE_DETACH_IOMMUFD_PT),
#endif
#ifdef VFIO_MIG_GET_PRECOPY_INFO
	IOCTL(VFIO_MIG_GET_PRECOPY_INFO),
#endif
#ifdef VFIO_IOMMU_ENABLE
	IOCTL(VFIO_IOMMU_ENABLE),
#endif
#ifdef VFIO_IOMMU_DISABLE
	IOCTL(VFIO_IOMMU_DISABLE),
#endif
#ifdef VFIO_IOMMU_SPAPR_TCE_GET_INFO
	IOCTL(VFIO_IOMMU_SPAPR_TCE_GET_INFO),
#endif
#ifdef VFIO_IOMMU_SPAPR_REGISTER_MEMORY
	IOCTL(VFIO_IOMMU_SPAPR_REGISTER_MEMORY),
#endif
#ifdef VFIO_IOMMU_SPAPR_UNREGISTER_MEMORY
	IOCTL(VFIO_IOMMU_SPAPR_UNREGISTER_MEMORY),
#endif
#ifdef VFIO_IOMMU_SPAPR_TCE_CREATE
	IOCTL(VFIO_IOMMU_SPAPR_TCE_CREATE),
#endif
#ifdef VFIO_IOMMU_SPAPR_TCE_REMOVE
	IOCTL(VFIO_IOMMU_SPAPR_TCE_REMOVE),
#endif
#ifdef VFIO_EEH_PE_OP
	IOCTL(VFIO_EEH_PE_OP),
#endif
};

/*
 * Per-VFIO ioctl struct-arg seeding.  Mirrors the kvm_vm_sanitise() pattern:
 * delegate ioctl selection to pick_random_ioctl(), then override rec->a3 for
 * the commands whose argument is a struct.  All VFIO ioctls are declared with
 * _IO() (no encoded size or direction), so the tiered arg-shape picker in
 * ioctls.c has no signal to work from and hands the kernel a random-shaped
 * buffer; every dma-map/unmap/get-info attempt then dies on argsz validation
 * before reaching the IOMMU dispatch.  The VFIO group is on the
 * efault_cache opt-out list so no probe leak is introduced here -- this
 * sanitiser replaces the random path entirely.
 */
#define VFIO_FUZZ_PAGE_SIZE	0x1000UL
#define VFIO_FUZZ_IOVA_LIMIT	(1UL << 40)
#define VFIO_FUZZ_MAX_ORDER	6		/* 4K .. 256K */
#define VFIO_FUZZ_MAX_INDEX	16

static void sanitise_vfio_dma_map(struct syscallrecord *rec)
{
	struct vfio_iommu_type1_dma_map *m;
	void *ua;
	__u64 size;

	m = get_writable_address(sizeof(*m));
	if (m == NULL)
		return;

	size = VFIO_FUZZ_PAGE_SIZE << rnd_modulo_u32(VFIO_FUZZ_MAX_ORDER + 1);

	/*
	 * vaddr must be page-aligned: the kernel's iommu_map() path masks
	 * it down to PAGE_SIZE before pinning.  Aligning down here (as an
	 * earlier revision did) would rewind up to page_size - 1 bytes
	 * back into the pool -- straight into `m` and whatever the prior
	 * sanitiser call left there -- so the kernel would map/pin those
	 * unrelated bytes and truncate the payload tail.  Pull a page-
	 * aligned reservation from the pool so [ua, ua + size) lies
	 * entirely inside our own allocation.
	 */
	ua = get_writable_page_aligned(size);
	if (ua == NULL)
		return;

	memset(m, 0, sizeof(*m));
	m->argsz = sizeof(*m);
	m->flags = ONE_IN(4)
		 ? VFIO_DMA_MAP_FLAG_READ
		 : (VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE);
	m->iova = rnd_modulo_u64(VFIO_FUZZ_IOVA_LIMIT)
		& ~(VFIO_FUZZ_PAGE_SIZE - 1);
	m->size = size;
	m->vaddr = (__u64)(unsigned long)ua;

	rec->a3 = (unsigned long)m;
}

static void sanitise_vfio_dma_unmap(struct syscallrecord *rec)
{
	struct vfio_iommu_type1_dma_unmap *u;
	__u64 size;

	u = get_writable_address(sizeof(*u));
	if (u == NULL)
		return;

	size = VFIO_FUZZ_PAGE_SIZE << rnd_modulo_u32(VFIO_FUZZ_MAX_ORDER + 1);

	memset(u, 0, sizeof(*u));
	u->argsz = sizeof(*u);
	if (ONE_IN(8))
		u->flags = VFIO_DMA_UNMAP_FLAG_ALL;
	else if (ONE_IN(8))
		u->flags = VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP;
	else
		u->flags = 0;
	if (u->flags & VFIO_DMA_UNMAP_FLAG_ALL) {
		u->iova = 0;
		u->size = 0;
	} else {
		u->iova = rnd_modulo_u64(VFIO_FUZZ_IOVA_LIMIT)
			& ~(VFIO_FUZZ_PAGE_SIZE - 1);
		u->size = size;
	}

	rec->a3 = (unsigned long)u;
}

static void sanitise_vfio_iommu_info(struct syscallrecord *rec)
{
	struct vfio_iommu_type1_info *info;

	info = get_writable_address(sizeof(*info));
	if (info == NULL)
		return;

	memset(info, 0, sizeof(*info));
	info->argsz = sizeof(*info);

	rec->a3 = (unsigned long)info;
}

static void sanitise_vfio_group_status(struct syscallrecord *rec)
{
	struct vfio_group_status *s;

	s = get_writable_address(sizeof(*s));
	if (s == NULL)
		return;

	memset(s, 0, sizeof(*s));
	s->argsz = sizeof(*s);

	rec->a3 = (unsigned long)s;
}

static void sanitise_vfio_device_info(struct syscallrecord *rec)
{
	struct vfio_device_info *info;

	info = get_writable_address(sizeof(*info));
	if (info == NULL)
		return;

	memset(info, 0, sizeof(*info));
	info->argsz = sizeof(*info);

	rec->a3 = (unsigned long)info;
}

static void sanitise_vfio_region_info(struct syscallrecord *rec)
{
	struct vfio_region_info *info;

	info = get_writable_address(sizeof(*info));
	if (info == NULL)
		return;

	memset(info, 0, sizeof(*info));
	info->argsz = sizeof(*info);
	info->index = rnd_modulo_u32(VFIO_FUZZ_MAX_INDEX);

	rec->a3 = (unsigned long)info;
}

static void sanitise_vfio_irq_info(struct syscallrecord *rec)
{
	struct vfio_irq_info *info;

	info = get_writable_address(sizeof(*info));
	if (info == NULL)
		return;

	memset(info, 0, sizeof(*info));
	info->argsz = sizeof(*info);
	info->index = rnd_modulo_u32(VFIO_FUZZ_MAX_INDEX);

	rec->a3 = (unsigned long)info;
}

#define VFIO_FUZZ_IRQ_MAX_COUNT	16

static void sanitise_vfio_irq_set(struct syscallrecord *rec)
{
	struct vfio_irq_set *s;
	__u32 count, data_len, data_flag;
	unsigned long total;
	__u8 *data;

	count = rnd_modulo_u32(VFIO_FUZZ_IRQ_MAX_COUNT + 1);

	switch (rnd_modulo_u32(3)) {
	case 0:
		data_flag = VFIO_IRQ_SET_DATA_NONE;
		data_len = 0;
		break;
	case 1:
		data_flag = VFIO_IRQ_SET_DATA_BOOL;
		data_len = count * sizeof(__u8);
		break;
	default:
		data_flag = VFIO_IRQ_SET_DATA_EVENTFD;
		data_len = count * sizeof(__s32);
		break;
	}

	total = sizeof(*s) + data_len;
	s = get_writable_address(total);
	if (s == NULL)
		return;

	memset(s, 0, total);
	s->argsz = total;

	switch (rnd_modulo_u32(3)) {
	case 0:
		s->flags = data_flag | VFIO_IRQ_SET_ACTION_MASK;
		break;
	case 1:
		s->flags = data_flag | VFIO_IRQ_SET_ACTION_UNMASK;
		break;
	default:
		s->flags = data_flag | VFIO_IRQ_SET_ACTION_TRIGGER;
		break;
	}

	s->index = rnd_modulo_u32(VFIO_FUZZ_MAX_INDEX);
	s->start = rnd_modulo_u32(VFIO_FUZZ_IRQ_MAX_COUNT);
	s->count = count;

	if (data_flag == VFIO_IRQ_SET_DATA_EVENTFD && count > 0) {
		__s32 *fds = (__s32 *)s->data;
		__u32 i;

		for (i = 0; i < count; i++)
			fds[i] = -1;
	} else if (data_len > 0) {
		data = s->data;
		memset(data, 0, data_len);
	}

	rec->a3 = (unsigned long)s;
}

#ifdef VFIO_DEVICE_IOEVENTFD
static void sanitise_vfio_device_ioeventfd(struct syscallrecord *rec)
{
	struct vfio_device_ioeventfd *e;
	static const __u32 widths[] = {
		VFIO_DEVICE_IOEVENTFD_8,
		VFIO_DEVICE_IOEVENTFD_16,
		VFIO_DEVICE_IOEVENTFD_32,
		VFIO_DEVICE_IOEVENTFD_64,
	};

	e = get_writable_address(sizeof(*e));
	if (e == NULL)
		return;

	memset(e, 0, sizeof(*e));
	e->argsz = sizeof(*e);
	e->flags = widths[rnd_modulo_u32(ARRAY_SIZE(widths))];
	e->fd = -1;

	rec->a3 = (unsigned long)e;
}
#endif

#ifdef VFIO_DEVICE_QUERY_GFX_PLANE
static void sanitise_vfio_gfx_plane(struct syscallrecord *rec)
{
	struct vfio_device_gfx_plane_info *p;
	static const __u32 types[] = {
		VFIO_GFX_PLANE_TYPE_PROBE,
		VFIO_GFX_PLANE_TYPE_DMABUF,
		VFIO_GFX_PLANE_TYPE_REGION,
	};

	p = get_writable_address(sizeof(*p));
	if (p == NULL)
		return;

	memset(p, 0, sizeof(*p));
	p->argsz = sizeof(*p);
	p->flags = types[rnd_modulo_u32(ARRAY_SIZE(types))];
	p->drm_plane_type = rnd_modulo_u32(VFIO_FUZZ_MAX_INDEX);

	rec->a3 = (unsigned long)p;
}
#endif

#ifdef VFIO_DEVICE_GET_GFX_DMABUF
static void sanitise_vfio_get_gfx_dmabuf(struct syscallrecord *rec)
{
	__u32 *id;

	id = get_writable_address(sizeof(*id));
	if (id == NULL)
		return;

	*id = 0;

	rec->a3 = (unsigned long)id;
}
#endif

#ifdef VFIO_MIG_GET_PRECOPY_INFO
static void sanitise_vfio_precopy_info(struct syscallrecord *rec)
{
	struct vfio_precopy_info *p;

	p = get_writable_address(sizeof(*p));
	if (p == NULL)
		return;

	memset(p, 0, sizeof(*p));
	p->argsz = sizeof(*p);

	rec->a3 = (unsigned long)p;
}
#endif

#ifdef VFIO_DEVICE_BIND_IOMMUFD
static void sanitise_vfio_bind_iommufd(struct syscallrecord *rec)
{
	struct vfio_device_bind_iommufd *b;

	b = get_writable_address(sizeof(*b));
	if (b == NULL)
		return;

	memset(b, 0, sizeof(*b));
	b->argsz = sizeof(*b);
	b->iommufd = -1;

	rec->a3 = (unsigned long)b;
}
#endif

#ifdef VFIO_DEVICE_ATTACH_IOMMUFD_PT
static void sanitise_vfio_attach_iommufd_pt(struct syscallrecord *rec)
{
	struct vfio_device_attach_iommufd_pt *a;

	a = get_writable_address(sizeof(*a));
	if (a == NULL)
		return;

	memset(a, 0, sizeof(*a));
	a->argsz = sizeof(*a);
	a->pt_id = rnd_modulo_u32(VFIO_FUZZ_MAX_INDEX);
	if (RAND_BOOL()) {
		a->flags |= VFIO_DEVICE_ATTACH_PASID;
		a->pasid = rnd_modulo_u32(VFIO_FUZZ_MAX_INDEX);
	}

	rec->a3 = (unsigned long)a;
}
#endif

#ifdef VFIO_DEVICE_DETACH_IOMMUFD_PT
static void sanitise_vfio_detach_iommufd_pt(struct syscallrecord *rec)
{
	struct vfio_device_detach_iommufd_pt *d;

	d = get_writable_address(sizeof(*d));
	if (d == NULL)
		return;

	memset(d, 0, sizeof(*d));
	d->argsz = sizeof(*d);
	if (RAND_BOOL()) {
		d->flags |= VFIO_DEVICE_DETACH_PASID;
		d->pasid = rnd_modulo_u32(VFIO_FUZZ_MAX_INDEX);
	}

	rec->a3 = (unsigned long)d;
}
#endif

#ifdef VFIO_DEVICE_GET_PCI_HOT_RESET_INFO
#define VFIO_FUZZ_HOT_RESET_MAX_COUNT	4

static void sanitise_vfio_hot_reset_info(struct syscallrecord *rec)
{
	struct vfio_pci_hot_reset_info *info;
	unsigned long total;
	__u32 count;

	count = rnd_modulo_u32(VFIO_FUZZ_HOT_RESET_MAX_COUNT) + 1;
	total = sizeof(*info) + count * sizeof(struct vfio_pci_dependent_device);

	info = get_writable_address(total);
	if (info == NULL)
		return;

	memset(info, 0, total);
	info->argsz = total;
	info->count = count;

	rec->a3 = (unsigned long)info;
}
#endif

#ifdef VFIO_DEVICE_FEATURE
#define VFIO_FUZZ_FEATURE_MAX_DATA	256

static void sanitise_vfio_device_feature(struct syscallrecord *rec)
{
	struct vfio_device_feature *f;
	__u32 data_len, op_flag;
	unsigned long total;

	data_len = rnd_modulo_u32(VFIO_FUZZ_FEATURE_MAX_DATA + 1);
	total = sizeof(*f) + data_len;

	f = get_writable_address(total);
	if (f == NULL)
		return;

	switch (rnd_modulo_u32(3)) {
	case 0:
		op_flag = VFIO_DEVICE_FEATURE_GET;
		break;
	case 1:
		op_flag = VFIO_DEVICE_FEATURE_SET;
		break;
	default:
		op_flag = VFIO_DEVICE_FEATURE_PROBE;
		break;
	}

	memset(f, 0, total);
	f->argsz = total;
	f->flags = op_flag | (rnd_modulo_u32(0x10000) & VFIO_DEVICE_FEATURE_MASK);

	rec->a3 = (unsigned long)f;
}
#endif

static void vfio_sanitise(const struct ioctl_group *grp,
			  struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case VFIO_IOMMU_MAP_DMA:
		sanitise_vfio_dma_map(rec);
		break;
	case VFIO_IOMMU_UNMAP_DMA:
#ifdef VFIO_DEVICE_QUERY_GFX_PLANE
		if (RAND_BOOL())
			sanitise_vfio_gfx_plane(rec);
		else
#endif
			sanitise_vfio_dma_unmap(rec);
		break;
	case VFIO_IOMMU_GET_INFO:
		/*
		 * VFIO_DEVICE_GET_PCI_HOT_RESET_INFO shares the same _IO()
		 * command number as VFIO_IOMMU_GET_INFO; the kernel
		 * disambiguates by which fd type the caller holds.  Toss a
		 * coin so both struct shapes get exercised.
		 */
#ifdef VFIO_DEVICE_GET_PCI_HOT_RESET_INFO
		if (RAND_BOOL())
			sanitise_vfio_hot_reset_info(rec);
		else
#endif
			sanitise_vfio_iommu_info(rec);
		break;
	case VFIO_GROUP_GET_STATUS:
		sanitise_vfio_group_status(rec);
		break;
	case VFIO_DEVICE_GET_INFO:
		sanitise_vfio_device_info(rec);
		break;
	case VFIO_DEVICE_GET_REGION_INFO:
		sanitise_vfio_region_info(rec);
		break;
	case VFIO_DEVICE_GET_IRQ_INFO:
		sanitise_vfio_irq_info(rec);
		break;
	case VFIO_DEVICE_SET_IRQS:
		sanitise_vfio_irq_set(rec);
		break;
#ifdef VFIO_DEVICE_FEATURE
	case VFIO_DEVICE_FEATURE:
		sanitise_vfio_device_feature(rec);
		break;
#endif
#ifdef VFIO_DEVICE_BIND_IOMMUFD
	case VFIO_DEVICE_BIND_IOMMUFD:
		sanitise_vfio_bind_iommufd(rec);
		break;
#endif
#ifdef VFIO_DEVICE_ATTACH_IOMMUFD_PT
	case VFIO_DEVICE_ATTACH_IOMMUFD_PT:
		sanitise_vfio_attach_iommufd_pt(rec);
		break;
#endif
#ifdef VFIO_DEVICE_DETACH_IOMMUFD_PT
	case VFIO_DEVICE_DETACH_IOMMUFD_PT:
		sanitise_vfio_detach_iommufd_pt(rec);
		break;
#endif
#ifdef VFIO_MIG_GET_PRECOPY_INFO
	case VFIO_MIG_GET_PRECOPY_INFO:
		sanitise_vfio_precopy_info(rec);
		break;
#endif
#ifdef VFIO_DEVICE_IOEVENTFD
	case VFIO_DEVICE_IOEVENTFD:
		sanitise_vfio_device_ioeventfd(rec);
		break;
#endif
#ifdef VFIO_DEVICE_GET_GFX_DMABUF
	case VFIO_DEVICE_GET_GFX_DMABUF:
		sanitise_vfio_get_gfx_dmabuf(rec);
		break;
#endif
	default:
		break;
	}
}

static const char *const vfio_devs[] = {
	"vfio",
};

static const struct ioctl_group vfio_grp = {
	.devtype = DEV_CHAR,
	.devs = vfio_devs,
	.devs_cnt = ARRAY_SIZE(vfio_devs),
	.sanitise = vfio_sanitise,
	.ioctls = vfio_ioctls,
	.ioctls_cnt = ARRAY_SIZE(vfio_ioctls),
};

REG_IOCTL_GROUP(vfio_grp)
#endif
