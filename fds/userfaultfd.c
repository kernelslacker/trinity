/* userfaultfd FDs */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/userfaultfd.h>

#include "fd.h"
#include "userfaultfd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"
#include "utils.h"

static int userfaultfd_create(__unused__ unsigned int flag)
{
#ifdef SYS_userfaultfd
	return syscall(SYS_userfaultfd, flag);
#else
	return -ENOSYS;
#endif
}

/*
 * Alternative path: open /dev/userfaultfd and issue USERFAULTFD_IOC_NEW
 * to get a userfaultfd.  Available since kernel v6.1.
 */
static int devuserfaultfd_create(unsigned int flag)
{
	int devfd, fd;

	devfd = open("/dev/userfaultfd", O_RDWR | O_CLOEXEC);
	if (devfd < 0)
		return -1;

	fd = ioctl(devfd, USERFAULTFD_IOC_NEW, (unsigned long)flag);
	close(devfd);
	return fd;
}

static void userfaultfd_destructor(struct object *obj)
{
	close(obj->userfaultobj.fd);
}

/*
 * Cross-process safe: only reads obj->userfaultobj fields (now in shm
 * via alloc_shared_obj) and the scope scalar.  No process-local
 * pointers are dereferenced, so it is correct to call this from a
 * different process than the one that allocated the obj — which
 * matters because head->dump runs from dump_childdata() in the
 * parent's crash diagnostics path even when a child triggered the
 * crash.
 */
static void userfaultfd_dump(struct object *obj, enum obj_scope scope)
{
	struct userfaultobj *uo = &obj->userfaultobj;

	output(2, "userfault fd:%d flags:%x scope:%d\n", uo->fd, uo->flags, scope);
}

/*
 * Perform the UFFDIO_API handshake so the kernel accepts subsequent
 * userfaultfd ioctls (UFFDIO_REGISTER, UFFDIO_COPY, etc.) on this fd.
 * Without the handshake, all other ioctls return -EINVAL.
 */
static void arm_userfaultfd(int fd)
{
	static const __u64 feature_flags[] = {
		UFFD_FEATURE_PAGEFAULT_FLAG_WP,
		UFFD_FEATURE_EVENT_FORK,
		UFFD_FEATURE_EVENT_REMAP,
		UFFD_FEATURE_EVENT_REMOVE,
		UFFD_FEATURE_MISSING_HUGETLBFS,
		UFFD_FEATURE_MISSING_SHMEM,
		UFFD_FEATURE_EVENT_UNMAP,
		UFFD_FEATURE_SIGBUS,
		UFFD_FEATURE_THREAD_ID,
		UFFD_FEATURE_MINOR_HUGETLBFS,
		UFFD_FEATURE_MINOR_SHMEM,
		UFFD_FEATURE_EXACT_ADDRESS,
		UFFD_FEATURE_WP_HUGETLBFS_SHMEM,
		UFFD_FEATURE_WP_UNPOPULATED,
		UFFD_FEATURE_POISON,
		UFFD_FEATURE_WP_ASYNC,
		UFFD_FEATURE_MOVE,
	};
	struct uffdio_api api;
	unsigned int i;

	memset(&api, 0, sizeof(api));
	api.api = UFFD_API;
	api.features = 0;
	for (i = 0; i < ARRAY_SIZE(feature_flags); i++) {
		if (rand() & 1)
			api.features |= feature_flags[i];
	}

	ioctl(fd, UFFDIO_API, &api);
}

static int open_userfaultfd(void)
{
	struct object *obj;
	int fd, flags;

	flags = RAND_BOOL() ? O_NONBLOCK : 0;
	if (RAND_BOOL())
		flags |= O_CLOEXEC;

	if (RAND_BOOL())
		fd = devuserfaultfd_create(flags);
	else
		fd = userfaultfd_create(flags);

	if (fd < 0) {
		outputerr("open_userfaultfd: userfaultfd creation failed: %s\n",
			strerror(errno));
		return false;
	}

	arm_userfaultfd(fd);

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		outputerr("open_userfaultfd: alloc_shared_obj failed\n");
		close(fd);
		return false;
	}
	obj->userfaultobj.fd = fd;
	obj->userfaultobj.flags = flags;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_USERFAULTFD);
	return true;
}

static int init_userfaultfds(void)
{
	struct objhead *head;
	unsigned int i;
	int ret = false;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_USERFAULTFD);
	head->destroy = &userfaultfd_destructor;
	head->dump = &userfaultfd_dump;
	/*
	 * Opt this provider into the shared obj heap.  __destroy_object()
	 * checks this flag to route the obj struct release through
	 * free_shared_obj() instead of free().  struct userfaultobj is
	 * {int fd; int flags;} — no pointer members — so the migration is
	 * purely mechanical.
	 */
	head->shared_alloc = true;

	for (i = 0; i < 4; i++) {
		if (open_userfaultfd())
			ret = true;
	}

	return ret;
}

static int get_rand_userfaultfd(void)
{
	if (objects_empty(OBJ_FD_USERFAULTFD) == true)
		return -1;

	/*
	 * Versioned slot pick + validate_object_handle() before the
	 * obj->userfaultobj.fd deref, mirroring the wireup at 15b6257b8206
	 * (fds/sockets.c get_rand_socketinfo) and 5ef98298f6ad
	 * (syscalls/keyctl.c KEYCTL_WATCH_KEY).  Same OBJ_GLOBAL lockless-
	 * reader UAF window the framework commit a7fdbb97830c spelled out:
	 * between the lockless slot pick and the consumer's read of
	 * the userfaultfd handed to ioctl(UFFDIO_*)/read via the fd_provider .get callback,
	 * the parent can destroy the obj, free_shared_obj() returns the
	 * chunk to the shared-heap freelist, and a concurrent
	 * alloc_shared_obj() recycles it underneath us.
	 */
	for (int i = 0; i < 1000; i++) {
		unsigned int slot_idx, slot_version;
		struct object *obj;
		int fd;

		obj = get_random_object_versioned(OBJ_FD_USERFAULTFD, OBJ_GLOBAL,
						  &slot_idx, &slot_version);
		if (obj == NULL)
			continue;

		/*
		 * Heap pointers land at >= 0x10000 and below the 47-bit
		 * user/kernel boundary; anything outside that window can't
		 * be a real obj struct.  Reject before deref.
		 */
		if ((uintptr_t)obj < 0x10000UL ||
		    (uintptr_t)obj >= 0x800000000000UL) {
			outputerr("get_rand_userfaultfd: bogus obj %p in "
				  "OBJ_FD_USERFAULTFD pool\n", obj);
			continue;
		}

		if (!validate_object_handle(OBJ_FD_USERFAULTFD, OBJ_GLOBAL, obj,
					    slot_idx, slot_version))
			continue;

		fd = obj->userfaultobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider userfaultfd_provider = {
	.name = "userfaultfd",
	.objtype = OBJ_FD_USERFAULTFD,
	.enabled = true,
	.init = &init_userfaultfds,
	.get = &get_rand_userfaultfd,
	.open = &open_userfaultfd,
};

REG_FD_PROV(userfaultfd_provider);
