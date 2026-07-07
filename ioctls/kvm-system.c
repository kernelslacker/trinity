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

/*
 * Match against the calling child's OBJ_LOCAL OBJ_FD_KVM_SYSTEM pool.
 * KVM object lifecycle moved from the parent-side .init hook onto a
 * per-child post-fork child_init: every system / VM / vCPU fd is now
 * created inside the child's own mm and lives in that child's
 * OBJ_LOCAL pool.  find_local_object_by_fd() is the O(1) hash probe
 * with a linear-fallback that the OBJ_LOCAL pool exposes for exactly
 * this shape of lookup.  OBJ_GLOBAL for these three types is empty
 * post-refactor.
 */
static int kvm_system_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	if (find_local_object_by_fd(OBJ_FD_KVM_SYSTEM, fd) != NULL)
		return 0;
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
