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

#include <string.h>
#include <linux/ioctl.h>
#include <linux/kvm.h>

#include "ioctls.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "utils.h"

#include "kernel/kvm.h"

/*
 * Compile-time: the struct each sanitiser fills for a fixed-shape
 * ioctl must match the _IOC_SIZE the request encodes.  A mismatch
 * means kernel headers moved under us and the sanitiser is
 * memset()ing / stamping into a buffer the kernel will read past
 * (over-encoded) or copy less of than we prepared (under-encoded).
 * Flex-tail requests (KVM_SET_GSI_ROUTING) and _IO() encodings
 * (KVM_SET_TSS_ADDR) are intentionally absent -- their _IOC_SIZE
 * counts only the header or is 0.
 */
IOCTL_SIZE_ASSERT(KVM_SET_USER_MEMORY_REGION, struct kvm_userspace_memory_region);
#ifdef KVM_SET_USER_MEMORY_REGION2
IOCTL_SIZE_ASSERT(KVM_SET_USER_MEMORY_REGION2, struct kvm_userspace_memory_region2);
#endif
IOCTL_SIZE_ASSERT(KVM_IRQ_LINE, struct kvm_irq_level);
IOCTL_SIZE_ASSERT(KVM_IRQ_LINE_STATUS, struct kvm_irq_level);
IOCTL_SIZE_ASSERT(KVM_CREATE_PIT2, struct kvm_pit_config);
IOCTL_SIZE_ASSERT(KVM_SET_IDENTITY_MAP_ADDR, __u64);

/*
 * Match against the calling child's OBJ_LOCAL OBJ_FD_KVM_VM pool.
 * See ioctls/kvm-system.c for the fuller rationale on why KVM fds
 * live in OBJ_LOCAL post-refactor.
 */
static int kvm_vm_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	if (find_local_object_by_fd(OBJ_FD_KVM_VM, fd) != NULL)
		return 0;
	return -1;
}

static const struct ioctl kvm_vm_ioctls[] = {
	IOCTL(KVM_CREATE_VCPU),
	IOCTL(KVM_GET_DIRTY_LOG),
	IOCTL(KVM_SET_NR_MMU_PAGES),
	IOCTL(KVM_GET_NR_MMU_PAGES),
	IOCTL(KVM_SET_USER_MEMORY_REGION),
#ifdef KVM_SET_USER_MEMORY_REGION2
	IOCTL(KVM_SET_USER_MEMORY_REGION2),
#endif
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
#ifdef KVM_GET_STATS_FD
	IOCTL(KVM_GET_STATS_FD),
#endif
#if defined(X86) && defined(KVM_HYPERV_EVENTFD)
	IOCTL(KVM_HYPERV_EVENTFD),
#endif
};

/*
 * Per-VM ioctl struct-arg seeding.  Mirrors the kvm_vcpu_sanitise() pattern:
 * delegate ioctl selection to pick_random_ioctl(), then override rec->a3 for
 * the cmds whose argument is a struct.  Tier 1's _IOC_SIZE-based generator
 * gives a header-sized writable buffer, which under-sizes the flexible array
 * tail on kvm_irq_routing (kernel walks `nr` entries past the buffer) and
 * leaves the fixed-size structs unconstrained (random slot indices outside
 * KVM_USER_MEM_SLOTS, unaligned guest_phys_addr / memory_size, etc), so
 * almost every dispatch bounces on -EINVAL before the kernel touches any
 * interesting code.
 */
#define KVM_FUZZ_PAGE_SIZE	0x1000UL
#define KVM_FUZZ_MEM_SLOTS	32
#define KVM_FUZZ_GPA_LIMIT	(1UL << 30)
#define KVM_FUZZ_MAX_MEM_SIZE	(16UL << 20)
#define KVM_FUZZ_MAX_ROUTING	16

static void sanitise_kvm_user_memory_region(struct syscallrecord *rec)
{
	struct kvm_userspace_memory_region *m;
	void *ua;

	m = get_writable_address(sizeof(*m));
	if (m == NULL)
		return;

	ua = get_writable_address(KVM_FUZZ_PAGE_SIZE);
	if (ua == NULL)
		return;

	m->slot = rnd_modulo_u32(KVM_FUZZ_MEM_SLOTS);
	m->flags = rnd_modulo_u32(2) ? 0 : KVM_MEM_LOG_DIRTY_PAGES;
	m->guest_phys_addr = (rnd_u64() % KVM_FUZZ_GPA_LIMIT)
			   & ~(KVM_FUZZ_PAGE_SIZE - 1);
	m->memory_size = (rnd_u64() % KVM_FUZZ_MAX_MEM_SIZE)
		       & ~(KVM_FUZZ_PAGE_SIZE - 1);
	m->userspace_addr = (__u64)(unsigned long)ua;

	rec->a3 = (unsigned long)m;
}

#ifdef KVM_SET_USER_MEMORY_REGION2
static void sanitise_kvm_user_memory_region2(struct syscallrecord *rec)
{
	struct kvm_userspace_memory_region2 *m;
	void *ua;

	m = get_writable_address(sizeof(*m));
	if (m == NULL)
		return;

	ua = get_writable_address(KVM_FUZZ_PAGE_SIZE);
	if (ua == NULL)
		return;

	memset(m, 0, sizeof(*m));

	m->slot = rnd_modulo_u32(KVM_FUZZ_MEM_SLOTS);
	m->flags = rnd_modulo_u32(2) ? 0 : KVM_MEM_LOG_DIRTY_PAGES;
	m->guest_phys_addr = (rnd_u64() % KVM_FUZZ_GPA_LIMIT)
			   & ~(KVM_FUZZ_PAGE_SIZE - 1);
	m->memory_size = (rnd_u64() % KVM_FUZZ_MAX_MEM_SIZE)
		       & ~(KVM_FUZZ_PAGE_SIZE - 1);
	m->userspace_addr = (__u64)(unsigned long)ua;

	rec->a3 = (unsigned long)m;
}
#endif

static void sanitise_kvm_irq_level(struct syscallrecord *rec)
{
	struct kvm_irq_level *l;

	l = get_writable_address(sizeof(*l));
	if (l == NULL)
		return;

	generate_rand_bytes((unsigned char *)l, sizeof(*l));
	l->irq = rnd_modulo_u32(256);
	l->level = rnd_modulo_u32(2);

	rec->a3 = (unsigned long)l;
}

#ifdef X86
static void sanitise_kvm_irq_routing(struct syscallrecord *rec)
{
	struct kvm_irq_routing *r;
	unsigned long sz;
	__u32 nr;

	nr = rnd_modulo_u32(KVM_FUZZ_MAX_ROUTING + 1);
	sz = sizeof(struct kvm_irq_routing)
	   + nr * sizeof(struct kvm_irq_routing_entry);

	r = get_writable_address(sz);
	if (r == NULL)
		return;

	generate_rand_bytes((unsigned char *)r, sz);
	r->nr = nr;
	r->flags = 0;

	rec->a3 = (unsigned long)r;
}
#endif

static void sanitise_kvm_pit_config(struct syscallrecord *rec)
{
	struct kvm_pit_config *c;

	c = get_writable_address(sizeof(*c));
	if (c == NULL)
		return;

	memset(c, 0, sizeof(*c));
	c->flags = rnd_modulo_u32(2) ? 0 : KVM_PIT_SPEAKER_DUMMY;

	rec->a3 = (unsigned long)c;
}

static void sanitise_kvm_u64_addr(struct syscallrecord *rec)
{
	__u64 *p;

	p = get_writable_address(sizeof(*p));
	if (p == NULL)
		return;

	*p = (rnd_u64() % KVM_FUZZ_GPA_LIMIT) & ~(KVM_FUZZ_PAGE_SIZE - 1);
	rec->a3 = (unsigned long)p;
}

static void kvm_vm_sanitise(const struct ioctl_group *grp,
			    struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case KVM_SET_USER_MEMORY_REGION:
		sanitise_kvm_user_memory_region(rec);
		break;
#ifdef KVM_SET_USER_MEMORY_REGION2
	case KVM_SET_USER_MEMORY_REGION2:
		sanitise_kvm_user_memory_region2(rec);
		break;
#endif
	case KVM_IRQ_LINE:
	case KVM_IRQ_LINE_STATUS:
		sanitise_kvm_irq_level(rec);
		break;
#ifdef X86
	case KVM_SET_GSI_ROUTING:
		sanitise_kvm_irq_routing(rec);
		break;
#endif
	case KVM_CREATE_PIT2:
		sanitise_kvm_pit_config(rec);
		break;
	case KVM_SET_IDENTITY_MAP_ADDR:
		sanitise_kvm_u64_addr(rec);
		break;
	case KVM_SET_TSS_ADDR:
		/* _IO encoding: arg is the address itself, not a pointer. */
		rec->a3 = (rnd_u64() % KVM_FUZZ_GPA_LIMIT)
			& ~(KVM_FUZZ_PAGE_SIZE - 1);
		break;
	default:
		break;
	}

	__atomic_add_fetch(&shm->stats.kvm.vm_ioctls_dispatched, 1,
			   __ATOMIC_RELAXED);
}

static const struct ioctl_group kvm_vm_grp = {
	.name = "kvm_vm",
	.fd_test = kvm_vm_fd_test,
	.sanitise = kvm_vm_sanitise,
	.ioctls = kvm_vm_ioctls,
	.ioctls_cnt = ARRAY_SIZE(kvm_vm_ioctls),
};

REG_IOCTL_GROUP(kvm_vm_grp)

#endif	/* USE_KVM */
