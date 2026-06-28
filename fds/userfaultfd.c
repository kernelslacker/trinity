/* userfaultfd FDs */

#include <errno.h>
#include <sys/ioctl.h>
#include <linux/userfaultfd.h>

#include "fd.h"
#include "syscall-gate.h"
#include "userfaultfd.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"
#include "utils.h"

static int userfaultfd_create(__unused__ unsigned int flag)
{
#ifdef SYS_userfaultfd
	return trinity_raw_syscall(SYS_userfaultfd, flag);
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

/*
 * Cross-process safe: only reads obj->userfaultobj scalar fields and
 * the scope scalar.  These survive fork/COW and no process-local
 * pointers are dereferenced, so it is correct to call this from a
 * different process than the one that allocated the obj — which matters
 * because head->dump runs from dump_childdata() in the parent's crash
 * diagnostics path even when a child triggered the crash.
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
		if (rnd_u32() & 1)
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
		int err = errno;
		enum fd_init_reason reason = (err == ENOSYS || err == ENXIO ||
					      err == ENODEV || err == ENOENT) ?
				FD_INIT_REASON_CONFIG_ABSENT :
				(err == EACCES || err == EPERM) ?
				FD_INIT_REASON_CAP_MISSING :
				FD_INIT_REASON_ERRNO;
		outputerr("open_userfaultfd: userfaultfd creation failed: %s\n",
			strerror(err));
		fd_provider_init_fail(reason, err, "userfaultfd_create");
		return false;
	}

	arm_userfaultfd(fd);

	obj = alloc_object();
	if (obj == NULL) {
		outputerr("open_userfaultfd: alloc_object failed\n");
		fd_provider_init_fail(FD_INIT_REASON_RESOURCE, 0, "alloc_object");
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
	head->destroy = &close_fd_destructor;
	head->dump = &userfaultfd_dump;
	/*
	 * struct userfaultobj is {int fd; int flags;} — no pointer members
	 * — so the OBJ_GLOBAL pool's scalars stay valid across fork/COW and
	 * cross-process reads are safe.
	 */

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
	 * Versioned slot pick + objpool_check() before the
	 * obj->userfaultobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the userfaultfd handed to ioctl(UFFDIO_*)/read via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_USERFAULTFD, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_USERFAULTFD))
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
	/*
	 * uffd_poll() blocks until the kernel has a pending page-fault event
	 * to deliver; with no registered VMA / no fault driver, EPOLL_CTL_ADD
	 * → ep_item_poll wedges the caller in TASK_UNINTERRUPTIBLE.  Bar from
	 * watch sets; direct read()/UFFDIO_* fuzzing remains unaffected.
	 */
	.poll_can_block = true,
};

REG_FD_PROV(userfaultfd_provider);
