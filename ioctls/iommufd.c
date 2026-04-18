
#ifdef USE_IOMMUFD
#include <linux/iommufd.h>

#include "utils.h"
#include "ioctls.h"

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

static const char *const iommufd_devs[] = {
	"iommu",
};

static const struct ioctl_group iommufd_grp = {
	.devtype = DEV_MISC,
	.devs = iommufd_devs,
	.devs_cnt = ARRAY_SIZE(iommufd_devs),
	.sanitise = pick_random_ioctl,
	.ioctls = iommufd_ioctls,
	.ioctls_cnt = ARRAY_SIZE(iommufd_ioctls),
};

REG_IOCTL_GROUP(iommufd_grp)
#endif
