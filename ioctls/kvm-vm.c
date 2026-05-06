/*
 * Per-VM ioctl grammar.
 *
 * Split out from the flat ioctls/kvm.c grouping.  VM-fd ioctls were
 * previously dispatched only when /dev/kvm itself was opened, where the
 * system fd would ENOTTY them.  This group registers an fd_test against
 * the OBJ_FD_KVM_VM pool populated by fds/kvm.c so VM ioctls fire on
 * real VM fds returned by KVM_CREATE_VM.  No DEV_MISC entry -- VM fds
 * are anonymous (kvm-vm) and do not appear under /proc/devices.
 *
 * KVM_ENABLE_CAP, KVM_SET_TSC_KHZ and KVM_GET_TSC_KHZ are dual-target
 * (VM + vCPU) ioctls that the kernel accepts on either fd.  Routed
 * here because the per-vCPU group at ioctls/kvm-vcpu.c does not
 * currently carry them and the spec for this split is to partition
 * the existing inventory rather than add new entries.
 */

#ifdef USE_KVM

#include <linux/ioctl.h>
#include <linux/kvm.h>

#include "ioctls.h"
#include "objects.h"
#include "shm.h"
#include "utils.h"

static int kvm_vm_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;

	head = &shm->global_objects[OBJ_FD_KVM_VM];

	for_each_obj(head, obj, idx) {
		if (obj->kvmvmobj.fd == fd)
			return 0;
	}

	return -1;
}

static const struct ioctl kvm_vm_ioctls[] = {
	IOCTL(KVM_CREATE_VCPU),
	IOCTL(KVM_GET_DIRTY_LOG),
	IOCTL(KVM_SET_NR_MMU_PAGES),
	IOCTL(KVM_GET_NR_MMU_PAGES),
	IOCTL(KVM_SET_USER_MEMORY_REGION),
	IOCTL(KVM_SET_TSS_ADDR),
	IOCTL(KVM_SET_IDENTITY_MAP_ADDR),
	IOCTL(KVM_CREATE_IRQCHIP),
	IOCTL(KVM_IRQ_LINE),
	IOCTL(KVM_GET_IRQCHIP),
	IOCTL(KVM_SET_IRQCHIP),
	IOCTL(KVM_CREATE_PIT),
	IOCTL(KVM_IRQ_LINE_STATUS),
	IOCTL(KVM_REGISTER_COALESCED_MMIO),
	IOCTL(KVM_UNREGISTER_COALESCED_MMIO),
	IOCTL(KVM_REINJECT_CONTROL),
	IOCTL(KVM_IRQFD),
	IOCTL(KVM_CREATE_PIT2),
	IOCTL(KVM_SET_BOOT_CPU_ID),
	IOCTL(KVM_IOEVENTFD),
	IOCTL(KVM_SET_CLOCK),
	IOCTL(KVM_GET_CLOCK),
#if defined(__powerpc__)
	IOCTL(KVM_PPC_GET_PVINFO),
#endif
	IOCTL(KVM_SET_TSC_KHZ),
	IOCTL(KVM_GET_TSC_KHZ),
	IOCTL(KVM_SIGNAL_MSI),
#ifdef X86
	IOCTL(KVM_GET_PIT),
	IOCTL(KVM_SET_PIT),
	IOCTL(KVM_GET_PIT2),
	IOCTL(KVM_SET_PIT2),
	IOCTL(KVM_SET_GSI_ROUTING),
	IOCTL(KVM_XEN_HVM_CONFIG),
#endif
#if defined(__powerpc__)
	IOCTL(KVM_PPC_GET_SMMU_INFO),
	IOCTL(KVM_PPC_ALLOCATE_HTAB),
#if defined(KVM_CREATE_SPAPR_TCE)
	IOCTL(KVM_CREATE_SPAPR_TCE),
#endif
#if defined(KVM_ALLOCATE_RMA)
	IOCTL(KVM_ALLOCATE_RMA),
#endif
	IOCTL(KVM_PPC_GET_HTAB_FD),
#endif
#if defined(__arm__) || defined(__aarch64__)
	IOCTL(KVM_ARM_SET_DEVICE_ADDR),
#endif
	IOCTL(KVM_ENABLE_CAP),
#ifdef KVM_RESET_DIRTY_RINGS
	IOCTL(KVM_RESET_DIRTY_RINGS),
#endif
#ifdef KVM_CLEAR_DIRTY_LOG
	IOCTL(KVM_CLEAR_DIRTY_LOG),
#endif
#ifdef KVM_SET_MEMORY_ATTRIBUTES
	IOCTL(KVM_SET_MEMORY_ATTRIBUTES),
#endif
#ifdef KVM_PRE_FAULT_MEMORY
	IOCTL(KVM_PRE_FAULT_MEMORY),
#endif
};

static const struct ioctl_group kvm_vm_grp = {
	.name = "kvm_vm",
	.fd_test = kvm_vm_fd_test,
	.sanitise = pick_random_ioctl,
	.ioctls = kvm_vm_ioctls,
	.ioctls_cnt = ARRAY_SIZE(kvm_vm_ioctls),
};

REG_IOCTL_GROUP(kvm_vm_grp)

#endif	/* USE_KVM */
