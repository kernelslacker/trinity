/*
 * /dev/kvm system-fd ioctl grammar.
 *
 * Split out from the flat ioctls/kvm.c grouping, which mixed system, VM
 * and vCPU ioctls under a single DEV_MISC "kvm" entry.  That layout only
 * fired when a child happened to grab /dev/kvm, and then dispatched any
 * ioctl in the inventory at the system fd -- VM- and vCPU-fd ioctls
 * landed there too and bounced off with ENOTTY.
 *
 * This file installs a dedicated ioctl_group with an fd_test that walks
 * the OBJ_FD_KVM_SYSTEM pool, so the system-fd ioctls only fire on
 * actual /dev/kvm fds.  DEV_MISC + devs="kvm" is kept as a fallback so
 * a /dev/kvm fd that never made it into the OBJ_FD_KVM_SYSTEM pool
 * (e.g. opened by some other code path) still dispatches here.
 */

#ifdef USE_KVM

#include <linux/ioctl.h>
#include <linux/kvm.h>

#include "ioctls.h"
#include "objects.h"
#include "shm.h"
#include "utils.h"

static int kvm_system_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;

	head = &shm->global_objects[OBJ_FD_KVM_SYSTEM];

	for_each_obj(head, obj, idx) {
		if (obj->kvmsysobj.fd == fd)
			return 0;
	}

	return -1;
}

static const struct ioctl kvm_system_ioctls[] = {
	IOCTL(KVM_GET_API_VERSION),
	IOCTL(KVM_CREATE_VM),
	IOCTL(KVM_CHECK_EXTENSION),
	IOCTL(KVM_GET_VCPU_MMAP_SIZE),
#ifdef KVM_TRACE_ENABLE
	IOCTL(KVM_TRACE_ENABLE),
#endif
#ifdef KVM_TRACE_PAUSE
	IOCTL(KVM_TRACE_PAUSE),
#endif
#ifdef KVM_TRACE_DISABLE
	IOCTL(KVM_TRACE_DISABLE),
#endif
#ifdef X86
	IOCTL(KVM_X86_GET_MCE_CAP_SUPPORTED),
#endif
};

static const char *const kvm_system_devs[] = {
	"kvm",
};

static const struct ioctl_group kvm_system_grp = {
	.name = "kvm_system",
	.devtype = DEV_MISC,
	.devs = kvm_system_devs,
	.devs_cnt = ARRAY_SIZE(kvm_system_devs),
	.fd_test = kvm_system_fd_test,
	.sanitise = pick_random_ioctl,
	.ioctls = kvm_system_ioctls,
	.ioctls_cnt = ARRAY_SIZE(kvm_system_ioctls),
};

REG_IOCTL_GROUP(kvm_system_grp)

#endif	/* USE_KVM */
