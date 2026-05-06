/* KVM fd provider — system + VM + vCPU (Phases 1-2). */

#ifdef USE_KVM

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kvm.h>

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
 * Tracks whether /dev/kvm could be opened at all.  Set by init_kvm_system
 * and consulted by init_kvm_vms / init_kvm_vcpus so all providers degrade
 * together when the kernel lacks KVM support (no module, headers but no
 * /dev/kvm node, EACCES, etc.).
 */
static bool kvm_subsystem_available = true;

/*
 * Cached KVM_GET_VCPU_MMAP_SIZE result — set by init_kvm_system right
 * after KVM_GET_API_VERSION succeeds, consumed by every create_one_vcpu()
 * call (init cascade and the .open regen path).  KVM_GET_VCPU_MMAP_SIZE
 * is a system-fd ioctl, so caching once at init avoids re-fetching it on
 * every vCPU creation.  Stays at 0 if the ioctl fails or returns an
 * unreasonable value, in which case kvm_run is left unmapped.
 */
static size_t kvm_vcpu_mmap_size;

static void kvm_vm_destructor(struct object *obj)
{
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
 * Tear down vCPU fds first, then VM fds, before closing the system fd.
 * destroy_global_objects() walks types in enum order and OBJ_FD_KVM_SYSTEM
 * precedes both OBJ_FD_KVM_VM and OBJ_FD_KVM_VCPU, so without this the
 * system fd is closed first and the kernel may reap the VM/vCPU fds out
 * from under us.  Mirror the perffd pattern: close peer fds inline (and
 * for vCPUs munmap the kvm_run page) and zero their fd / NULL their
 * kvm_run field so the later type-walk's call to kvm_vcpu_destructor /
 * kvm_vm_destructor sees the cleared state and skips the duplicate
 * close()/munmap().
 *
 * vCPU teardown precedes VM teardown because each vCPU fd is parented
 * by a VM fd: closing the VM first would orphan the vCPU mapping at the
 * kernel side and the subsequent munmap on the per-vCPU kvm_run region
 * would race against KVM's destroy path.  Same ordering the kernel
 * itself enforces — kvm_destroy_vm() reaps vCPUs before tearing down
 * the kvm struct.
 */
static void kvm_system_destructor(struct object *obj)
{
	struct objhead *vcpuhead = get_objhead(OBJ_GLOBAL, OBJ_FD_KVM_VCPU);
	struct objhead *vmhead = get_objhead(OBJ_GLOBAL, OBJ_FD_KVM_VM);

	if (vcpuhead != NULL && vcpuhead->array != NULL) {
		struct object *peer;
		unsigned int idx;

		for_each_obj(vcpuhead, peer, idx) {
			if (peer->kvmvcpuobj.kvm_run != NULL) {
				munmap(peer->kvmvcpuobj.kvm_run,
				       peer->kvmvcpuobj.kvm_run_size);
				peer->kvmvcpuobj.kvm_run = NULL;
			}
			if (peer->kvmvcpuobj.fd < 0)
				continue;
			close(peer->kvmvcpuobj.fd);
			peer->kvmvcpuobj.fd = -1;
		}
	}

	if (vmhead != NULL && vmhead->array != NULL) {
		struct object *peer;
		unsigned int idx;

		for_each_obj(vmhead, peer, idx) {
			if (peer->kvmvmobj.fd < 0)
				continue;
			close(peer->kvmvmobj.fd);
			peer->kvmvmobj.fd = -1;
		}
	}

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

static void setup_kvm_vm_head(void)
{
	struct objhead *head = get_objhead(OBJ_GLOBAL, OBJ_FD_KVM_VM);

	head->destroy = &kvm_vm_destructor;
	head->dump = &kvm_vm_dump;
	head->shared_alloc = true;
}

static void setup_kvm_vcpu_head(void)
{
	struct objhead *head = get_objhead(OBJ_GLOBAL, OBJ_FD_KVM_VCPU);

	head->destroy = &kvm_vcpu_destructor;
	head->dump = &kvm_vcpu_dump;
	head->shared_alloc = true;
}

/*
 * Walk the OBJ_FD_KVM_SYSTEM pool and return the first live system fd.
 * Plain linear pick — Phase 1 only ever creates one system fd, and this
 * runs from init context (parent only, before fork) so the lockless-
 * reader UAF protections that get_rand_kvm_*_fd needs aren't relevant.
 */
static int peek_system_fd(void)
{
	struct objhead *head = get_objhead(OBJ_GLOBAL, OBJ_FD_KVM_SYSTEM);
	struct object *obj;
	unsigned int idx;

	if (head == NULL || head->array == NULL)
		return -1;

	for_each_obj(head, obj, idx) {
		if (obj->kvmsysobj.fd >= 0)
			return obj->kvmsysobj.fd;
	}
	return -1;
}

/*
 * Walk the OBJ_FD_KVM_VM pool and return the first live VM obj.  Used
 * by the init cascade to chain a vCPU into the VM that create_one_vm
 * just added, and by the vCPU regen path to find any live VM to parent
 * a replacement vCPU under.  Same init-context-only contract as
 * peek_system_fd: parent only, no lockless-reader hazard window.
 */
static struct object *peek_vm_obj(void)
{
	struct objhead *head = get_objhead(OBJ_GLOBAL, OBJ_FD_KVM_VM);
	struct object *obj;
	unsigned int idx;

	if (head == NULL || head->array == NULL)
		return NULL;

	for_each_obj(head, obj, idx) {
		if (obj->kvmvmobj.fd >= 0)
			return obj;
	}
	return NULL;
}

/*
 * Create one vCPU on the supplied VM and add it to the OBJ_FD_KVM_VCPU
 * pool.  KVM_CREATE_VCPU's argument is the per-VM vcpu_id; pull the
 * next id off the VM's nr_vcpus counter so back-to-back creations on
 * the same VM advance through 0, 1, 2, ... rather than colliding on 0
 * (kernel returns -EEXIST if vcpu_id is already used on that VM).
 *
 * After KVM_CREATE_VCPU succeeds we mmap the kvm_run page on the new
 * vCPU fd at offset 0 with size cached in kvm_vcpu_mmap_size (set by
 * init_kvm_system from KVM_GET_VCPU_MMAP_SIZE).  kvm_run is the
 * kernel↔userspace shared region used by KVM_RUN to publish exit
 * reasons; not strictly needed for the read-side ioctls Phase 2 leaves
 * available, but mapping it now means the vCPU fd is fully constructed
 * the moment Phase 4's KVM_RUN ioctl grammar lands.  We pass MAP_SHARED
 * (kvm_run is one struct, kernel-published, must be visible to both
 * sides) and route the resulting region through track_shared_region()
 * so the mm-syscall sanitisers refuse a fuzzed munmap/mremap targeting
 * it -- same defence io_uring's SQ ring + SQE array use.
 *
 * On any failure after KVM_CREATE_VCPU succeeds (mmap, alloc_shared_obj)
 * we close the vCPU fd before returning false so the kernel-side vCPU
 * state and the userspace fd are released together rather than leaking.
 * If kvm_vcpu_mmap_size is 0 (init failed to cache it) we skip the mmap
 * and register the vCPU with kvm_run=NULL; the destructor's NULL guard
 * keeps the munmap path safe.
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

	vcpu_id = vmobj->kvmvmobj.nr_vcpus;
	vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)vcpu_id);
	if (vcpufd < 0) {
		outputerr("init_kvm: KVM_CREATE_VCPU(vmfd=%d, id=%d) failed: %s\n",
			vmfd, vcpu_id, strerror(errno));
		return false;
	}

	if (kvm_vcpu_mmap_size > 0) {
		kvm_run_sz = kvm_vcpu_mmap_size;
		kvm_run = mmap(NULL, kvm_run_sz, PROT_READ | PROT_WRITE,
			       MAP_SHARED, vcpufd, 0);
		if (kvm_run == MAP_FAILED) {
			outputerr("init_kvm: mmap(kvm_run, sz=%zu, vcpufd=%d) failed: %s\n",
				kvm_run_sz, vcpufd, strerror(errno));
			close(vcpufd);
			return false;
		}
		track_shared_region((unsigned long)kvm_run, kvm_run_sz);
	}

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		outputerr("init_kvm: alloc_shared_obj(vcpu) failed\n");
		if (kvm_run != NULL)
			munmap(kvm_run, kvm_run_sz);
		close(vcpufd);
		return false;
	}
	obj->kvmvcpuobj.fd = vcpufd;
	obj->kvmvcpuobj.parent_vmfd = vmfd;
	obj->kvmvcpuobj.vcpu_id = vcpu_id;
	obj->kvmvcpuobj.kvm_run = kvm_run;
	obj->kvmvcpuobj.kvm_run_size = kvm_run_sz;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_KVM_VCPU);

	vmobj->kvmvmobj.nr_vcpus++;
	return true;
}

/*
 * Populate vmobj with KVM_VCPUS_PER_VM vCPUs.  Best-effort: each vCPU is
 * an independent object in the OBJ_FD_KVM_VCPU pool, so a partial result
 * (one of two creates failed) is still useful and the caller doesn't need
 * to roll the first vCPU back.  NULL vmobj passes through to
 * create_one_vcpu()'s own NULL guard.
 */
static void create_vcpus_for_vm(struct object *vmobj)
{
	int i;

	for (i = 0; i < KVM_VCPUS_PER_VM; i++)
		(void)create_one_vcpu(vmobj);
}

static bool create_one_vm(int sysfd)
{
	struct object *obj;
	int vmfd;

	vmfd = ioctl(sysfd, KVM_CREATE_VM, 0UL);
	if (vmfd < 0) {
		outputerr("init_kvm: KVM_CREATE_VM failed: %s\n",
			strerror(errno));
		return false;
	}

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		outputerr("init_kvm: alloc_shared_obj(vm) failed\n");
		close(vmfd);
		return false;
	}
	obj->kvmvmobj.fd = vmfd;
	obj->kvmvmobj.parent_sysfd = sysfd;
	obj->kvmvmobj.nr_vcpus = 0;
	obj->kvmvmobj.nr_devices = 0;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_KVM_VM);
	return true;
}

static int init_kvm_system(void)
{
	struct objhead *syshead;
	struct object *sysobj;
	int sysfd, api_version, mmap_size;

	syshead = get_objhead(OBJ_GLOBAL, OBJ_FD_KVM_SYSTEM);
	syshead->destroy = &kvm_system_destructor;
	syshead->dump = &kvm_system_dump;
	syshead->shared_alloc = true;

	/*
	 * Prepare the VM and vCPU heads here too — the cascade below adds
	 * OBJ_FD_KVM_VM and OBJ_FD_KVM_VCPU objects, and add_object() will
	 * route them through whichever destroy callback is wired up at the
	 * time of insertion.  Idempotent re-set later from init_kvm_vms /
	 * init_kvm_vcpus is harmless.
	 */
	setup_kvm_vm_head();
	setup_kvm_vcpu_head();

	sysfd = open("/dev/kvm", O_RDWR);
	if (sysfd < 0) {
		outputerr("init_kvm_system: open(/dev/kvm) failed: %s\n",
			strerror(errno));
		kvm_subsystem_available = false;
		return false;
	}

	api_version = ioctl(sysfd, KVM_GET_API_VERSION, 0UL);
	if (api_version < 0) {
		outputerr("init_kvm_system: KVM_GET_API_VERSION failed: %s\n",
			strerror(errno));
		close(sysfd);
		kvm_subsystem_available = false;
		return false;
	}
	if (api_version != KVM_EXPECTED_API_VERSION) {
		outputerr("init_kvm_system: unexpected KVM API version %d (expected %d)\n",
			api_version, KVM_EXPECTED_API_VERSION);
	}

	/*
	 * Cache the kvm_run mmap size off the system fd while we still have
	 * easy access to one.  KVM_GET_VCPU_MMAP_SIZE returns the per-vCPU
	 * shared region size in bytes — a small kernel-fixed value (one or a
	 * few pages on every supported arch) — so anything outside a sane
	 * page-aligned band signals a broken kernel and we leave the cache
	 * at 0, which makes create_one_vcpu() skip the mmap.  The vCPU is
	 * still useful for the read-side per-vCPU ioctls without kvm_run.
	 */
	mmap_size = ioctl(sysfd, KVM_GET_VCPU_MMAP_SIZE, 0UL);
	if (mmap_size > 0 && (size_t)mmap_size <= (1UL << 20))
		kvm_vcpu_mmap_size = (size_t)mmap_size;
	else
		outputerr("init_kvm_system: KVM_GET_VCPU_MMAP_SIZE returned %d (errno=%s)\n",
			mmap_size, strerror(errno));

	sysobj = alloc_shared_obj(sizeof(struct object));
	if (sysobj == NULL) {
		outputerr("init_kvm_system: alloc_shared_obj(sys) failed\n");
		close(sysfd);
		kvm_subsystem_available = false;
		return false;
	}
	sysobj->kvmsysobj.fd = sysfd;
	sysobj->kvmsysobj.api_version = api_version;
	add_object(sysobj, OBJ_GLOBAL, OBJ_FD_KVM_SYSTEM);

	/*
	 * Cascade into VM and vCPU creation so a single init pass leaves all
	 * three pools populated regardless of which provider's init runs
	 * first (fds.c randomises init order).  Best-effort: if KVM_CREATE_VM
	 * fails the system provider is still useful for system-level ioctls;
	 * if the VM lands but KVM_CREATE_VCPU fails, the VM remains for VM-
	 * level ioctls.
	 */
	if (create_one_vm(sysfd))
		create_vcpus_for_vm(peek_vm_obj());

	return true;
}

static int init_kvm_vms(void)
{
	if (!kvm_subsystem_available)
		return false;

	setup_kvm_vm_head();

	/*
	 * If init_kvm_system already ran and cascaded a VM into the pool,
	 * nothing to do.  If init_kvm_vms ran first and the system pool is
	 * still empty, return success and let init_kvm_system populate the
	 * VM pool when it cascades — try_regenerate_fd() will keep the pool
	 * topped up later.
	 */
	if (!objects_empty(OBJ_FD_KVM_VM))
		return true;

	if (objects_empty(OBJ_FD_KVM_SYSTEM))
		return true;

	/*
	 * Defensive cascade: if we land here it means the system pool was
	 * populated by some path other than init_kvm_system's full cascade
	 * (e.g. system init partially failed after add_object, or a future
	 * regen path topped up only the system fd).  Mirror init_kvm_system's
	 * full chain so the vCPU pool gets populated with the per-VM
	 * KVM_VCPUS_PER_VM count rather than relying on regen to top it up
	 * later.
	 */
	if (create_one_vm(peek_system_fd()))
		create_vcpus_for_vm(peek_vm_obj());
	return true;
}

static int init_kvm_vcpus(void)
{
	if (!kvm_subsystem_available)
		return false;

	setup_kvm_vcpu_head();

	/*
	 * Mirror init_kvm_vms's defensive shape: if init_kvm_system already
	 * cascaded vCPUs into the pool, nothing to do.  If we ran before
	 * the VM pool was populated, return success and let the cascade
	 * (or try_regenerate_fd) populate the vCPU pool later.
	 */
	if (!objects_empty(OBJ_FD_KVM_VCPU))
		return true;

	if (objects_empty(OBJ_FD_KVM_VM))
		return true;

	create_vcpus_for_vm(peek_vm_obj());
	return true;
}

static int open_kvm_system_fd(void)
{
	struct object *obj;
	int sysfd, api_version;

	if (!kvm_subsystem_available)
		return false;

	sysfd = open("/dev/kvm", O_RDWR);
	if (sysfd < 0)
		return false;

	api_version = ioctl(sysfd, KVM_GET_API_VERSION, 0UL);
	if (api_version < 0) {
		close(sysfd);
		return false;
	}

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(sysfd);
		return false;
	}
	obj->kvmsysobj.fd = sysfd;
	obj->kvmsysobj.api_version = api_version;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_KVM_SYSTEM);
	return true;
}

static int open_kvm_vm_fd(void)
{
	int sysfd;

	if (!kvm_subsystem_available)
		return false;

	sysfd = peek_system_fd();
	if (sysfd < 0)
		return false;

	return create_one_vm(sysfd) ? true : false;
}

static int open_kvm_vcpu_fd(void)
{
	struct object *vmobj;

	if (!kvm_subsystem_available)
		return false;

	vmobj = peek_vm_obj();
	if (vmobj == NULL)
		return false;

	return create_one_vcpu(vmobj) ? true : false;
}

static int get_rand_kvm_system_fd(void)
{
	if (objects_empty(OBJ_FD_KVM_SYSTEM) == true)
		return -1;

	for (int i = 0; i < 1000; i++) {
		unsigned int slot_idx, slot_version;
		struct object *obj;
		int fd;

		obj = get_random_object_versioned(OBJ_FD_KVM_SYSTEM, OBJ_GLOBAL,
						  &slot_idx, &slot_version);
		if (obj == NULL)
			continue;

		if ((uintptr_t)obj < 0x10000UL ||
		    (uintptr_t)obj >= 0x800000000000UL) {
			outputerr("get_rand_kvm_system_fd: bogus obj %p in "
				  "OBJ_FD_KVM_SYSTEM pool\n", obj);
			continue;
		}

		if (!validate_object_handle(OBJ_FD_KVM_SYSTEM, OBJ_GLOBAL, obj,
					    slot_idx, slot_version))
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
	if (objects_empty(OBJ_FD_KVM_VM) == true)
		return -1;

	for (int i = 0; i < 1000; i++) {
		unsigned int slot_idx, slot_version;
		struct object *obj;
		int fd;

		obj = get_random_object_versioned(OBJ_FD_KVM_VM, OBJ_GLOBAL,
						  &slot_idx, &slot_version);
		if (obj == NULL)
			continue;

		if ((uintptr_t)obj < 0x10000UL ||
		    (uintptr_t)obj >= 0x800000000000UL) {
			outputerr("get_rand_kvm_vm_fd: bogus obj %p in "
				  "OBJ_FD_KVM_VM pool\n", obj);
			continue;
		}

		if (!validate_object_handle(OBJ_FD_KVM_VM, OBJ_GLOBAL, obj,
					    slot_idx, slot_version))
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
	if (objects_empty(OBJ_FD_KVM_VCPU) == true)
		return -1;

	for (int i = 0; i < 1000; i++) {
		unsigned int slot_idx, slot_version;
		struct object *obj;
		int fd;

		obj = get_random_object_versioned(OBJ_FD_KVM_VCPU, OBJ_GLOBAL,
						  &slot_idx, &slot_version);
		if (obj == NULL)
			continue;

		if ((uintptr_t)obj < 0x10000UL ||
		    (uintptr_t)obj >= 0x800000000000UL) {
			outputerr("get_rand_kvm_vcpu_fd: bogus obj %p in "
				  "OBJ_FD_KVM_VCPU pool\n", obj);
			continue;
		}

		if (!validate_object_handle(OBJ_FD_KVM_VCPU, OBJ_GLOBAL, obj,
					    slot_idx, slot_version))
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
	.get = &get_rand_kvm_system_fd,
	.open = &open_kvm_system_fd,
};

REG_FD_PROV(kvm_system_provider);

static const struct fd_provider kvm_vm_provider = {
	.name = "kvm_vm",
	.objtype = OBJ_FD_KVM_VM,
	.enabled = true,
	.init = &init_kvm_vms,
	.get = &get_rand_kvm_vm_fd,
	.open = &open_kvm_vm_fd,
};

REG_FD_PROV(kvm_vm_provider);

static const struct fd_provider kvm_vcpu_provider = {
	.name = "kvm_vcpu",
	.objtype = OBJ_FD_KVM_VCPU,
	.enabled = true,
	.init = &init_kvm_vcpus,
	.get = &get_rand_kvm_vcpu_fd,
	.open = &open_kvm_vcpu_fd,
};

REG_FD_PROV(kvm_vcpu_provider);

#endif /* USE_KVM */
