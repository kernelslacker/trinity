/*
 * Per-vCPU ioctl grammar.
 *
 * Phase 1 (6a98d474117f) and Phase 2 (11222fbf1656) wired up the KVM fd
 * hierarchy: /dev/kvm -> KVM_CREATE_VM -> KVM_CREATE_VCPU, with vCPU fds
 * landing in OBJ_FD_KVM_VCPU.  Until the read-side commit landed, those
 * vCPU fds were exercisable only by the flat ioctls/kvm.c grouping,
 * which matches against the "kvm" misc-device name and so only ever
 * fires when a child happens to grab /dev/kvm itself -- in which case
 * the per-vCPU ioctls in that grouping bounce off the system fd with
 * ENOTTY.  This file installs a dedicated ioctl_group with an fd_test
 * that walks the OBJ_FD_KVM_VCPU pool, so per-vCPU ioctls only fire on
 * actual vCPU fds.
 *
 * Read-side ioctls (KVM_GET_*) populate userspace buffers from kernel
 * vCPU state and never mutate the vCPU; write-side ioctls (KVM_SET_*,
 * KVM_INTERRUPT, KVM_NMI, KVM_SMI) take userspace input and update
 * vCPU register state, queue interrupts, deliver NMIs, etc.  Both sets
 * share kvm_vcpu_sanitise() and the same kvm_vcpu_grp registration --
 * find_ioctl_group()'s fd_test arbitration is the only place fd-type
 * dispatch matters, and there's no per-direction split there.
 */

#ifdef USE_KVM

#include <stdlib.h>
#include <string.h>
#include <linux/ioctl.h>
#include <linux/kvm.h>

#ifdef X86
#include <asm/kvm.h>
#endif

#include "ioctls.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"

/*
 * Match against the OBJ_FD_KVM_VCPU pool populated by fds/kvm.c.  Linear
 * scan -- the pool tops out at KVM_VCPUS_PER_VM * (max VMs created at
 * init + regenerated), well under the threshold where O(n) hurts.  Same
 * shape as userfaultfd_fd_test / vduse_fd_test for programmatically-
 * created fds that have no /proc/devices presence to match on.
 */
static int kvm_vcpu_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;

	head = &shm->global_objects[OBJ_FD_KVM_VCPU];

	for_each_obj(head, obj, idx) {
		if (obj->kvmvcpuobj.fd == fd)
			return 0;
	}

	return -1;
}

/*
 * Variable-length kvm_msrs / kvm_cpuid2 / kvm_reg_list bounds for the
 * fuzz path.  The Tier 1 ioctl arg generator only sees the fixed header
 * size from the request encoding (8 bytes for kvm_msrs / kvm_cpuid2,
 * 8 for kvm_reg_list) and would seed the leading count field with random
 * bytes -- which on KVM_GET_MSRS would set nmsrs to a random gigabyte
 * count and either bail on EINVAL or have the kernel write past the
 * 8-byte buffer into adjacent heap.  Cap at small bounded counts so the
 * tail allocation is always sized to hold what nmsrs / nent / n claims,
 * and randomise the rest of the buffer so the kernel still sees varied
 * entry indices on the read path's filter-by-known-MSR / filter-by-leaf
 * codepaths.
 */
#define KVM_FUZZ_MAX_MSRS	16
#define KVM_FUZZ_MAX_CPUID	32
#define KVM_FUZZ_MAX_REGS	32

#ifdef X86
static void sanitise_kvm_msrs(struct syscallrecord *rec)
{
	struct kvm_msrs *m;
	unsigned long sz;

	sz = sizeof(struct kvm_msrs)
	   + KVM_FUZZ_MAX_MSRS * sizeof(struct kvm_msr_entry);

	m = get_writable_address(sz);
	if (m == NULL)
		return;

	generate_rand_bytes((unsigned char *)m, sz);
	m->nmsrs = (__u32)(rand() % (KVM_FUZZ_MAX_MSRS + 1));
	m->pad = 0;

	rec->a3 = (unsigned long)m;
}

static void sanitise_kvm_cpuid2(struct syscallrecord *rec)
{
	struct kvm_cpuid2 *c;
	unsigned long sz;

	sz = sizeof(struct kvm_cpuid2)
	   + KVM_FUZZ_MAX_CPUID * sizeof(struct kvm_cpuid_entry2);

	c = get_writable_address(sz);
	if (c == NULL)
		return;

	generate_rand_bytes((unsigned char *)c, sz);
	c->nent = (__u32)(rand() % (KVM_FUZZ_MAX_CPUID + 1));
	c->padding = 0;

	rec->a3 = (unsigned long)c;
}
#endif

static void sanitise_kvm_reg_list(struct syscallrecord *rec)
{
	struct kvm_reg_list *r;
	unsigned long sz;

	sz = sizeof(struct kvm_reg_list) + KVM_FUZZ_MAX_REGS * sizeof(__u64);

	r = get_writable_address(sz);
	if (r == NULL)
		return;

	generate_rand_bytes((unsigned char *)r, sz);
	r->n = (__u64)(rand() % (KVM_FUZZ_MAX_REGS + 1));

	rec->a3 = (unsigned long)r;
}

static void kvm_vcpu_sanitise(const struct ioctl_group *grp,
			      struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	/*
	 * Override Tier 1's writable-buffer sizing for the variable-length
	 * structs whose flexible array tail is sized by the leading count
	 * field.  The standard generator gives an _IOC_SIZE-sized buffer
	 * (the header alone), which on the GET path has the kernel writing
	 * past the buffer when the randomised count field exceeds zero, and
	 * on the SET path has the kernel reading past the buffer when it
	 * walks entries[] expecting nmsrs / nent items.  KVM_SET_MSRS /
	 * KVM_SET_CPUID2 share the same struct shape as their GET twin and
	 * route through the same helper.
	 */
	switch (rec->a2) {
#ifdef X86
	case KVM_GET_MSRS:
	case KVM_SET_MSRS:
		sanitise_kvm_msrs(rec);
		break;
	case KVM_GET_CPUID2:
	case KVM_SET_CPUID2:
		sanitise_kvm_cpuid2(rec);
		break;
#endif
	case KVM_GET_REG_LIST:
		sanitise_kvm_reg_list(rec);
		break;
	default:
		break;
	}

	__atomic_add_fetch(&shm->stats.kvm_vcpu_ioctls_dispatched, 1,
			   __ATOMIC_RELAXED);
}

static const struct ioctl kvm_vcpu_ioctls[] = {
	IOCTL(KVM_GET_REGS),
	IOCTL(KVM_SET_REGS),
	IOCTL(KVM_GET_SREGS),
	IOCTL(KVM_SET_SREGS),
	IOCTL(KVM_GET_FPU),
	IOCTL(KVM_SET_FPU),
	IOCTL(KVM_GET_VCPU_EVENTS),
	IOCTL(KVM_SET_VCPU_EVENTS),
	IOCTL(KVM_INTERRUPT),
	IOCTL(KVM_NMI),
#ifdef KVM_SMI
	IOCTL(KVM_SMI),
#endif
#ifdef X86
	IOCTL(KVM_GET_LAPIC),
	IOCTL(KVM_SET_LAPIC),
	IOCTL(KVM_GET_MSRS),
	IOCTL(KVM_SET_MSRS),
	IOCTL(KVM_GET_CPUID2),
	IOCTL(KVM_SET_CPUID2),
	IOCTL(KVM_GET_XSAVE),
	IOCTL(KVM_SET_XSAVE),
	IOCTL(KVM_GET_XCRS),
	IOCTL(KVM_SET_XCRS),
	IOCTL(KVM_GET_DEBUGREGS),
	IOCTL(KVM_SET_DEBUGREGS),
#endif
	IOCTL(KVM_GET_REG_LIST),
};

static const struct ioctl_group kvm_vcpu_grp = {
	.name = "kvm_vcpu",
	.fd_test = kvm_vcpu_fd_test,
	.sanitise = kvm_vcpu_sanitise,
	.ioctls = kvm_vcpu_ioctls,
	.ioctls_cnt = ARRAY_SIZE(kvm_vcpu_ioctls),
};

REG_IOCTL_GROUP(kvm_vcpu_grp)

#endif /* USE_KVM */
