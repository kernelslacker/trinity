/* KVM fd provider — system + VM (Phase 1). */

#ifdef USE_KVM

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/kvm.h>

#include "fd.h"
#include "objects.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define KVM_EXPECTED_API_VERSION 12

/*
 * Tracks whether /dev/kvm could be opened at all.  Set by init_kvm_system
 * and consulted by init_kvm_vms so both providers degrade together when
 * the kernel lacks KVM support (no module, headers but no /dev/kvm node,
 * EACCES, etc.).
 */
static bool kvm_subsystem_available = true;

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

/*
 * Tear down VM fds before closing the system fd.  destroy_global_objects()
 * walks types in enum order and OBJ_FD_KVM_SYSTEM precedes OBJ_FD_KVM_VM,
 * so without this the system fd is closed first and the kernel may reap
 * the VM fds out from under us.  Mirror the perffd pattern: close peer
 * fds inline and zero their fd field so the later type-walk's call to
 * kvm_vm_destructor sees -1 and skips the close().
 */
static void kvm_system_destructor(struct object *obj)
{
	struct objhead *vmhead = get_objhead(OBJ_GLOBAL, OBJ_FD_KVM_VM);

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
	int sysfd, api_version;

	syshead = get_objhead(OBJ_GLOBAL, OBJ_FD_KVM_SYSTEM);
	syshead->destroy = &kvm_system_destructor;
	syshead->dump = &kvm_system_dump;
	syshead->shared_alloc = true;

	/*
	 * Prepare the VM head here too — the cascade below adds OBJ_FD_KVM_VM
	 * objects, and add_object() will route them through whichever destroy
	 * callback is wired up at the time of insertion.  Idempotent re-set
	 * later from init_kvm_vms is harmless.
	 */
	setup_kvm_vm_head();

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
	 * Cascade into VM creation so a single init pass leaves the pool
	 * populated regardless of which provider's init runs first (fds.c
	 * randomises init order).  Best-effort: if KVM_CREATE_VM fails the
	 * system provider is still useful for system-level ioctls.
	 */
	(void)create_one_vm(sysfd);

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

	(void)create_one_vm(peek_system_fd());
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

#endif /* USE_KVM */
