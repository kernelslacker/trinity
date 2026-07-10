
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

	ua = get_writable_address(size);
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

static void vfio_sanitise(const struct ioctl_group *grp,
			  struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case VFIO_IOMMU_MAP_DMA:
		sanitise_vfio_dma_map(rec);
		break;
	case VFIO_IOMMU_UNMAP_DMA:
		sanitise_vfio_dma_unmap(rec);
		break;
	case VFIO_IOMMU_GET_INFO:
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
