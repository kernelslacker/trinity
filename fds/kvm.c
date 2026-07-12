/* KVM fd provider — system + VM + vCPU (Phases 1-2). */

#ifdef USE_KVM

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kvm.h>

#include "child.h"
#include "fd.h"
#include "objects.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define KVM_EXPECTED_API_VERSION 12

/*
 * Number of vCPUs created per VM at init time.  2 covers the cross-vCPU
 * code paths the kernel exercises only when a VM has more than one vCPU
 * (KVM_RUN concurrency, IPI delivery, lapic state sharing across vCPUs,
 * MSR scope behavior) without paying the per-vCPU resource cost of higher
 * counts.  The vcpu_id passed to KVM_CREATE_VCPU is sourced from
 * vmobj->kvmvmobj.nr_vcpus, so back-to-back calls advance through 0, 1,
 * ... naturally; each vCPU lands in OBJ_FD_KVM_VCPU as its own object
 * with its own slot-version handle, so get_random_object_versioned()
 * picks between them at fuzz time.
 */
#define KVM_VCPUS_PER_VM 2

/*
 * Latched per-process: /dev/kvm could not be opened or KVM_GET_API_VERSION
 * failed.  Set by init_kvm_system (parent-side probe) and consulted by
 * kvm_child_init and the get_rand_kvm_*_fd consumers so every child
 * degrades together when the kernel lacks KVM support (no module,
 * headers but no /dev/kvm node, EACCES, etc.).  Mirrors the
 * unsupported_<name> flag shape used by landlock / memfd_secret / mq.
 * Written pre-fork so children observe the parent's value; child-side
 * open() failures fall through to per-child skipping, no re-latching
 * needed.
 */
static bool unsupported_kvm;

/*
 * Cached KVM_GET_VCPU_MMAP_SIZE result -- captured pre-fork by
 * init_kvm_system so every child inherits the same value, consumed by
 * kvm_child_init's per-child vCPU creation loop.  KVM_GET_VCPU_MMAP_SIZE
 * is a kernel-fixed value, so a single probe is authoritative for the
 * whole run.  Stays at 0 if the ioctl fails or returns an unreasonable
 * value, in which case kvm_run is left unmapped and the vCPU is still
 * useful for the read-side per-vCPU ioctls.
 */
static size_t kvm_vcpu_mmap_size;

static void kvm_vm_destructor(struct object *obj)
{
	if (obj->kvmvmobj.guest_ram != NULL) {
		untrack_shared_region((unsigned long)obj->kvmvmobj.guest_ram,
				      obj->kvmvmobj.guest_ram_size);
		munmap(obj->kvmvmobj.guest_ram, obj->kvmvmobj.guest_ram_size);
		obj->kvmvmobj.guest_ram = NULL;
	}
	if (obj->kvmvmobj.fd >= 0) {
		close(obj->kvmvmobj.fd);
		obj->kvmvmobj.fd = -1;
	}
}

static void kvm_vm_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "kvm_vm fd:%d parent_sysfd:%d nr_vcpus:%d nr_devices:%d scope:%d\n",
		obj->kvmvmobj.fd, obj->kvmvmobj.parent_sysfd,
		obj->kvmvmobj.nr_vcpus, obj->kvmvmobj.nr_devices, scope);
}

static void kvm_vcpu_destructor(struct object *obj)
{
	if (obj->kvmvcpuobj.kvm_run != NULL) {
		untrack_shared_region((unsigned long)obj->kvmvcpuobj.kvm_run,
				      obj->kvmvcpuobj.kvm_run_size);
		munmap(obj->kvmvcpuobj.kvm_run, obj->kvmvcpuobj.kvm_run_size);
		obj->kvmvcpuobj.kvm_run = NULL;
	}
	if (obj->kvmvcpuobj.fd >= 0) {
		close(obj->kvmvcpuobj.fd);
		obj->kvmvcpuobj.fd = -1;
	}
}

static void kvm_vcpu_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "kvm_vcpu fd:%d parent_vmfd:%d vcpu_id:%d kvm_run:%p size:%zu scope:%d\n",
		obj->kvmvcpuobj.fd, obj->kvmvcpuobj.parent_vmfd,
		obj->kvmvcpuobj.vcpu_id, obj->kvmvcpuobj.kvm_run,
		obj->kvmvcpuobj.kvm_run_size, scope);
}

/*
 * Close the system fd.  No inline peer walk any more: KVM objects now
 * live in the calling child's OBJ_LOCAL pool, which has no whole-pool
 * teardown call site -- the child _exit()s and the kernel releases the
 * per-child mm (unmapping kvm_run + guest_ram) and closes every child-
 * owned fd (vCPU, VM, system) as part of process teardown.  The pre-
 * refactor peer walk existed to defend against destroy_global_objects()
 * closing the OBJ_GLOBAL system fd before the VM / vCPU fds; there is
 * no equivalent OBJ_LOCAL teardown path, and no other caller invokes
 * destroy_object() on a KVM object today.
 *
 * If a future path ever adds explicit per-object destroy for KVM
 * (fuzz-driven KVM_DESTROY_VM, coverage-frontier eviction, etc.) it
 * must reap the per-VM vCPUs and per-VM guest_ram in the same call
 * -- the kernel-side ordering (vCPUs first, then VM) matches what
 * kvm_destroy_vm() enforces internally.
 */
static void kvm_system_destructor(struct object *obj)
{
	if (obj->kvmsysobj.fd >= 0) {
		close(obj->kvmsysobj.fd);
		obj->kvmsysobj.fd = -1;
	}
}

static void kvm_system_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "kvm_system fd:%d api_version:%d scope:%d\n",
		obj->kvmsysobj.fd, obj->kvmsysobj.api_version, scope);
}

/*
 * Wire the OBJ_GLOBAL heads' destroy + dump slots.  OBJ_GLOBAL is empty
 * for these three types post-refactor -- every KVM object lives in the
 * calling child's OBJ_LOCAL pool -- but init_object_lists(OBJ_LOCAL)
 * copies max_entries / destroy / dump from the OBJ_GLOBAL head into the
 * child's OBJ_LOCAL head, so wiring them on the parent side is what
 * gets the same destructors installed for every child's OBJ_LOCAL
 * entries.  Called once from init_kvm_system's parent-side probe.
 */
static void setup_kvm_heads(void)
{
	struct objhead *head;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_KVM_SYSTEM);
	head->destroy = &kvm_system_destructor;
	head->dump = &kvm_system_dump;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_KVM_VM);
	head->destroy = &kvm_vm_destructor;
	head->dump = &kvm_vm_dump;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_KVM_VCPU);
	head->destroy = &kvm_vcpu_destructor;
	head->dump = &kvm_vcpu_dump;
}

/*
 * Minimal guest seed.  With no memslot and no code the vCPU faults on
 * entry and every KVM_RUN returns FAIL_ENTRY/SHUTDOWN, leaving the
 * IO/MMIO/HLT exit handlers unreachable.  Install one small RAM region
 * at gpa 0 holding a tiny real-mode program:
 *   mov al,0x42 ; out 0x00,al ; mov [0x8000],al ; hlt
 * so a single KVM_RUN takes a real exit -- KVM_EXIT_IO (the out), then
 * KVM_EXIT_MMIO (the store to gpa 0x8000, above RAM so un-backed), then
 * KVM_EXIT_HLT.  Everything past this first real exit (page tables,
 * multi-exit guests, dirty-log-feeding loops) is left to follow-ons.
 */
#define KVM_GUEST_RAM_SIZE	(4U * 4096U)

static const unsigned char kvm_guest_code[] = {
	0xb0, 0x42,		/* mov   al, 0x42                       */
	0xe6, 0x00,		/* out   0x00, al     -> KVM_EXIT_IO    */
	0xa2, 0x00, 0x80,	/* mov   [0x8000], al -> KVM_EXIT_MMIO  */
	0xf4,			/* hlt                -> KVM_EXIT_HLT   */
};

static void kvm_seed_guest(struct object *vmobj)
{
	struct kvm_userspace_memory_region region = { 0 };
	void *ram;

	ram = mmap(NULL, KVM_GUEST_RAM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (ram == MAP_FAILED)
		return;		/* best-effort: the VM is still usable un-seeded */

	memcpy(ram, kvm_guest_code, sizeof(kvm_guest_code));

	region.slot = 0;
	region.guest_phys_addr = 0;
	region.memory_size = KVM_GUEST_RAM_SIZE;
	region.userspace_addr = (uintptr_t)ram;
	if (ioctl(vmobj->kvmvmobj.fd, KVM_SET_USER_MEMORY_REGION,
		  &region) < 0) {
		munmap(ram, KVM_GUEST_RAM_SIZE);
		return;
	}

	/* Same defence kvm_run + the io_uring rings use: the mm-syscall
	 * sanitisers refuse a fuzzed munmap/mremap against a tracked region,
	 * so a stray guest-RAM unmap can't yank the memslot out. */
	track_shared_region((unsigned long)ram, KVM_GUEST_RAM_SIZE);
	vmobj->kvmvmobj.guest_ram = ram;
	vmobj->kvmvmobj.guest_ram_size = KVM_GUEST_RAM_SIZE;
}

/*
 * Point a vCPU at the seeded guest: flat real-mode entry at gpa 0.  The
 * architectural reset state already leaves ds/es/ss 0-based, so only CS
 * (base + selector) and rip need overriding.  Best-effort -- a vCPU
 * whose regs can't be set is still useful for the register ioctls, it
 * just won't take the seeded exit.
 */
static void kvm_seed_vcpu_regs(int vcpufd)
{
#if defined(__x86_64__) || defined(__i386__)
	struct kvm_sregs sregs;
	struct kvm_regs regs = { 0 };

	if (ioctl(vcpufd, KVM_GET_SREGS, &sregs) < 0)
		return;
	sregs.cs.base = 0;
	sregs.cs.selector = 0;
	if (ioctl(vcpufd, KVM_SET_SREGS, &sregs) < 0)
		return;

	regs.rip = 0;
	regs.rflags = 0x2;	/* reserved bit 1 set; interrupts left off */
	regs.rsp = 0x2000;	/* valid SP inside guest RAM (code uses none) */
	(void)ioctl(vcpufd, KVM_SET_REGS, &regs);
#else
	/* The seeded entry state above is x86 flat-real-mode specific
	 * (CS/RIP/RSP/RFLAGS); other arches have no equivalent register
	 * layout, so leave the vCPU at its architectural reset state -- it
	 * is still useful for the register ioctls, per the note above. */
	(void)vcpufd;
#endif
}

/*
 * Create one vCPU on the supplied VM and add it to the calling child's
 * OBJ_LOCAL OBJ_FD_KVM_VCPU pool.  KVM_CREATE_VCPU's argument is the
 * per-VM vcpu_id; pull the next id off the VM's nr_vcpus counter so
 * back-to-back creations on the same VM advance through 0, 1, 2, ...
 * rather than colliding on 0 (kernel returns -EEXIST if vcpu_id is
 * already used on that VM).  Runs from the per-child fd_provider
 * child_init hook so the vCPU is created inside this child's mm --
 * KVM stamps vcpu->kvm->mm at creation time and every subsequent
 * ioctl compares that against current->mm.
 *
 * After KVM_CREATE_VCPU succeeds we mmap the kvm_run page on the new
 * vCPU fd at offset 0 with size cached in kvm_vcpu_mmap_size (captured
 * pre-fork by init_kvm_system).  kvm_run is the kernel-userspace shared
 * region KVM_RUN publishes exit reasons through.  MAP_SHARED (kvm_run
 * is one struct, kernel-published, must be visible to both sides)
 * routed through track_shared_region() so the mm-syscall sanitisers
 * refuse a fuzzed munmap/mremap targeting it -- same defence
 * io_uring's SQ ring + SQE array use.
 *
 * On any failure after KVM_CREATE_VCPU succeeds (mmap, alloc_object)
 * we close the vCPU fd before returning false so the kernel-side vCPU
 * state and the userspace fd are released together rather than
 * leaking.  If kvm_vcpu_mmap_size is 0 (probe failed to cache it) we
 * skip the mmap and register the vCPU with kvm_run=NULL; the
 * destructor's NULL guard keeps the munmap path safe.
 */
static bool create_one_vcpu(struct object *vmobj)
{
	struct object *obj;
	void *kvm_run = NULL;
	size_t kvm_run_sz = 0;
	int vcpufd, vcpu_id, vmfd;

	if (vmobj == NULL)
		return false;

	vmfd = vmobj->kvmvmobj.fd;
	if (vmfd < 0)
		return false;

	vcpu_id = __atomic_fetch_add(&vmobj->kvmvmobj.nr_vcpus, 1, __ATOMIC_RELAXED);
	vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)vcpu_id);
	if (vcpufd < 0)
		return false;

	if (kvm_vcpu_mmap_size > 0) {
		kvm_run_sz = kvm_vcpu_mmap_size;
		kvm_run = mmap(NULL, kvm_run_sz, PROT_READ | PROT_WRITE,
			       MAP_SHARED, vcpufd, 0);
		if (kvm_run == MAP_FAILED) {
			close(vcpufd);
			return false;
		}
		track_shared_region((unsigned long)kvm_run, kvm_run_sz);
	}

	kvm_seed_vcpu_regs(vcpufd);

	obj = alloc_object();
	if (obj == NULL) {
		if (kvm_run != NULL) {
			untrack_shared_region((unsigned long)kvm_run,
					      kvm_run_sz);
			munmap(kvm_run, kvm_run_sz);
		}
		close(vcpufd);
		return false;
	}
	obj->kvmvcpuobj.fd = vcpufd;
	obj->kvmvcpuobj.parent_vmfd = vmfd;
	obj->kvmvcpuobj.vcpu_id = vcpu_id;
	obj->kvmvcpuobj.kvm_run = kvm_run;
	obj->kvmvcpuobj.kvm_run_size = kvm_run_sz;
	add_object(obj, OBJ_LOCAL, OBJ_FD_KVM_VCPU);

	return true;
}

/*
 * Create one VM against @sysfd (this child's own /dev/kvm fd) and add
 * it to the calling child's OBJ_LOCAL OBJ_FD_KVM_VM pool, together
 * with KVM_VCPUS_PER_VM vCPUs on that VM.  Runs from the per-child
 * fd_provider child_init hook so vcpu->kvm->mm resolves to this
 * child's mm on every subsequent per-VM / per-vCPU ioctl.
 *
 * vCPU creation is done before add_object() publishes the VM: once
 * the pool takes ownership of obj, an internal rejection path
 * (bad-fd guard, snapshot-missing head, grow-alloc failure) may
 * release the slot straight back to the deferred-free ring, so
 * dereferencing obj after that point could touch reclaimed memory.
 * Best-effort throughout -- a partial vCPU set is still useful, and
 * a failed add_object() leaves the vCPUs (whose parent_vmfd captured
 * the raw fd, not an obj pointer) intact for the child's fuzz loop.
 */
static void create_one_vm(int sysfd)
{
	struct object *obj;
	int vmfd, i;

	vmfd = ioctl(sysfd, KVM_CREATE_VM, 0UL);
	if (vmfd < 0)
		return;

	obj = alloc_object();
	if (obj == NULL) {
		close(vmfd);
		return;
	}
	obj->kvmvmobj.fd = vmfd;
	obj->kvmvmobj.parent_sysfd = sysfd;
	obj->kvmvmobj.nr_vcpus = 0;
	obj->kvmvmobj.nr_devices = 0;
	obj->kvmvmobj.guest_ram = NULL;
	obj->kvmvmobj.guest_ram_size = 0;
	kvm_seed_guest(obj);

	for (i = 0; i < KVM_VCPUS_PER_VM; i++)
		(void)create_one_vcpu(obj);

	add_object(obj, OBJ_LOCAL, OBJ_FD_KVM_VM);
}

/*
 * Parent-side probe.  Runs pre-fork once, from the fds/fds.c dispatcher.
 * Sole responsibility now:
 *   - wire the OBJ_GLOBAL heads' destroy / dump slots so
 *     init_object_lists(OBJ_LOCAL) inherits them into every child's
 *     per-type head,
 *   - open /dev/kvm long enough to verify KVM_GET_API_VERSION and cache
 *     KVM_GET_VCPU_MMAP_SIZE for every child to inherit,
 *   - close the probe sysfd and return: NO object is added to
 *     OBJ_GLOBAL.  All three pools stay empty on the parent side; every
 *     KVM object -- system / VM / vCPU -- is created per-child in
 *     kvm_child_init() so vcpu->kvm->mm lands on the child's mm and
 *     subsequent per-vCPU / per-VM ioctls do not trip the
 *     vcpu->kvm->mm != current->mm check in kvm_main.c
 *     (kvm_vcpu_ioctl / kvm_vm_ioctl at the mm mismatch return -EIO,
 *     which pre-refactor made every child's KVM_RUN error).
 *
 * unsupported_kvm latching is inherited by every child across fork, so
 * a probe failure here disables the child_init path fleet-wide without
 * further coordination.
 */
static int init_kvm_system(void)
{
	int sysfd, api_version, mmap_size;

	setup_kvm_heads();

	sysfd = open("/dev/kvm", O_RDWR);
	if (sysfd < 0) {
		outputerr("init_kvm_system: open(/dev/kvm) failed: %s -- latching unsupported_kvm\n",
			strerror(errno));
		unsupported_kvm = true;
		return false;
	}

	api_version = ioctl(sysfd, KVM_GET_API_VERSION, 0UL);
	if (api_version < 0) {
		outputerr("init_kvm_system: KVM_GET_API_VERSION failed: %s -- latching unsupported_kvm\n",
			strerror(errno));
		close(sysfd);
		unsupported_kvm = true;
		return false;
	}
	if (api_version != KVM_EXPECTED_API_VERSION) {
		outputerr("init_kvm_system: unexpected KVM API version %d (expected %d)\n",
			api_version, KVM_EXPECTED_API_VERSION);
	}

	/*
	 * Cache the kvm_run mmap size off the probe sysfd.  A single
	 * pre-fork probe is authoritative -- KVM_GET_VCPU_MMAP_SIZE
	 * returns a kernel-fixed per-arch constant that does not vary
	 * per fd or per task.  Anything outside a sane page-aligned
	 * band leaves the cache at 0, which makes create_one_vcpu() skip
	 * the mmap; the vCPU is still useful for the read-side per-vCPU
	 * ioctls without kvm_run.
	 */
	mmap_size = ioctl(sysfd, KVM_GET_VCPU_MMAP_SIZE, 0UL);
	if (mmap_size > 0 && (size_t)mmap_size <= (1UL << 20))
		kvm_vcpu_mmap_size = (size_t)mmap_size;
	else
		outputerr("init_kvm_system: KVM_GET_VCPU_MMAP_SIZE returned %d (errno=%s)\n",
			mmap_size, strerror(errno));

	/*
	 * Close the probe fd -- children re-open /dev/kvm in kvm_child_init
	 * so the system fd owned by each child's OBJ_LOCAL pool is a fresh
	 * kernel-side struct kvm_dev bound to nothing.  Keeping the parent
	 * sysfd open and adding it to OBJ_GLOBAL was the pre-refactor
	 * shape; it inherited into every child via fork but was never used,
	 * and the VM/vCPU objects created against it were the unreachable
	 * (mm mismatch) objects this stack removes.
	 */
	close(sysfd);
	return true;
}

/*
 * Per-child KVM bring-up.  Wired to the fd_provider child_init hook
 * on kvm_system_provider (VM / vCPU providers share the same
 * child-init step and leave their own child_init NULL).  Runs from
 * init_child() after init_child_setup_sandbox() so the child's
 * kernel-object view matches what the fuzz loop will see (uid /
 * namespaces / rlimits already tightened) and before
 * init_child_runtime_config() so the RLIMIT_AS 4 GiB pin does not
 * clip legitimate KVM mmaps at bring-up time.
 *
 * Sequence: open /dev/kvm into this child's mm, publish as OBJ_LOCAL
 * OBJ_FD_KVM_SYSTEM, create one VM against that sysfd and seed its
 * guest RAM, create KVM_VCPUS_PER_VM vCPUs on that VM with kvm_run
 * mmap + register seed.  Best-effort at every step: a failure at
 * any stage leaves whatever succeeded so far intact for the child's
 * fuzz loop to reach (system fd for KVM_CHECK_EXTENSION,
 * KVM_GET_API_VERSION; VM fd for KVM_SET_USER_MEMORY_REGION,
 * KVM_GET_DIRTY_LOG; vCPU fds for KVM_GET_REGS / KVM_SET_REGS).
 */
static void kvm_child_init(struct childdata *child __attribute__((unused)))
{
	struct object *sysobj;
	int sysfd;

	if (unsupported_kvm)
		return;

	sysfd = open("/dev/kvm", O_RDWR);
	if (sysfd < 0)
		return;

	sysobj = alloc_object();
	if (sysobj == NULL) {
		close(sysfd);
		return;
	}
	sysobj->kvmsysobj.fd = sysfd;
	sysobj->kvmsysobj.api_version = KVM_EXPECTED_API_VERSION;
	add_object(sysobj, OBJ_LOCAL, OBJ_FD_KVM_SYSTEM);

	create_one_vm(sysfd);
}

/*
 * VM / vCPU fd_provider init hooks: no work to do at parent-side .init
 * -- the whole KVM chain is stood up per-child in kvm_child_init, and
 * this .init exists only to give the provider a non-NULL init slot so
 * the fds/fds.c dispatcher marks it initialised (which is what unlocks
 * the child_init walk in the calling child, plus keeps the provider's
 * .get accessible from get_new_random_fd).  Returning true unconditionally
 * matches the shape used by every other zero-parent-work provider.
 */
static int init_kvm_vms(void)
{
	if (unsupported_kvm)
		return false;
	return true;
}

static int init_kvm_vcpus(void)
{
	if (unsupported_kvm)
		return false;
	return true;
}

/*
 * Per-child (OBJ_LOCAL) KVM fd pickers.  Every KVM object (system fd,
 * VM fd, vCPU fd) lives in the calling child's private OBJ_LOCAL pool
 * -- the kernel binds each object to the creating task's mm at
 * KVM_CREATE_VM / KVM_CREATE_VCPU time and every subsequent ioctl
 * compares vcpu->kvm->mm against current->mm.  A parent-created object
 * inherited across fork is unreachable from every child (kvm_main.c
 * kvm_vcpu_ioctl / kvm_vm_ioctl at the mm mismatch return -EIO), so
 * the parent-side OBJ_GLOBAL pool used pre-refactor was never usable
 * from fuzz context and every KVM_RUN in every child errored.
 *
 * objects_pool_empty() short-circuits on an empty local pool; the
 * bounded per-child retry loop then mirrors the OBJ_GLOBAL pickers
 * that lived here before.  OBJ_LOCAL is per-child and not exposed to
 * the lockless-reader UAF window OBJ_GLOBAL guards against, but we
 * still run objpool_check() -- cheap and matches the fd-provider
 * defensive shape used elsewhere in this file.
 */
static int get_rand_kvm_system_fd(void)
{
	if (unsupported_kvm)
		return -1;

	if (objects_pool_empty(OBJ_LOCAL, OBJ_FD_KVM_SYSTEM) == true)
		return -1;

	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_KVM_SYSTEM, OBJ_LOCAL);
		if (!objpool_check(obj, OBJ_FD_KVM_SYSTEM))
			continue;

		fd = obj->kvmsysobj.fd;
		if (fd < 0)
			continue;
		return fd;
	}
	return -1;
}

static int get_rand_kvm_vm_fd(void)
{
	if (unsupported_kvm)
		return -1;

	if (objects_pool_empty(OBJ_LOCAL, OBJ_FD_KVM_VM) == true)
		return -1;

	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_KVM_VM, OBJ_LOCAL);
		if (!objpool_check(obj, OBJ_FD_KVM_VM))
			continue;

		fd = obj->kvmvmobj.fd;
		if (fd < 0)
			continue;
		return fd;
	}
	return -1;
}

static int get_rand_kvm_vcpu_fd(void)
{
	if (unsupported_kvm)
		return -1;

	if (objects_pool_empty(OBJ_LOCAL, OBJ_FD_KVM_VCPU) == true)
		return -1;

	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_KVM_VCPU, OBJ_LOCAL);
		if (!objpool_check(obj, OBJ_FD_KVM_VCPU))
			continue;

		fd = obj->kvmvcpuobj.fd;
		if (fd < 0)
			continue;
		return fd;
	}
	return -1;
}

static const struct fd_provider kvm_system_provider = {
	.name = "kvm_system",
	.objtype = OBJ_FD_KVM_SYSTEM,
	.enabled = true,
	.init = &init_kvm_system,
	/*
	 * Whole KVM object chain (system fd, VM, vCPUs) is created here
	 * per-child.  Only the kvm_system_provider carries the child_init
	 * -- the VM / vCPU providers ride along via the same call.
	 */
	.child_init = &kvm_child_init,
	.get = &get_rand_kvm_system_fd,
};

REG_FD_PROV(kvm_system_provider);

static const struct fd_provider kvm_vm_provider = {
	.name = "kvm_vm",
	.objtype = OBJ_FD_KVM_VM,
	.enabled = true,
	.init = &init_kvm_vms,
	.get = &get_rand_kvm_vm_fd,
};

REG_FD_PROV(kvm_vm_provider);

static const struct fd_provider kvm_vcpu_provider = {
	.name = "kvm_vcpu",
	.objtype = OBJ_FD_KVM_VCPU,
	.enabled = true,
	.init = &init_kvm_vcpus,
	.get = &get_rand_kvm_vcpu_fd,
	/*
	 * kvm_vcpu_fops->poll runs through the KVM_RUN waitqueue; without
	 * an actively scheduled vCPU thread, ep_item_poll has nothing to
	 * wake it.  Bar from epoll/select/poll watch sets; direct
	 * KVM_RUN/KVM_GET_REGS ioctl fuzzing remains available.
	 */
	.poll_can_block = true,
};

REG_FD_PROV(kvm_vcpu_provider);

#endif /* USE_KVM */
