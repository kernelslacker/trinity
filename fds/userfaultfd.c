/* userfaultfd FDs */

#include <errno.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "child.h"
#include "fd.h"
#include "kernel/userfaultfd.h"
#include "syscall-gate.h"
#include "userfaultfd.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
static int userfaultfd_create(__unused__ unsigned int flag)
{
#ifdef SYS_userfaultfd
	return trinity_raw_syscall(SYS_userfaultfd, flag);
#else
	errno = ENOSYS;
	return -1;
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
 * Create a userfaultfd for the calling process, shared by the pool
 * seeder below and the pagemap_wp_scan childop.  UFFD_USER_MODE_ONLY
 * is ORed in: children run as nobody with an empty capability set
 * and vm.unprivileged_userfaultfd at its default 0, so
 * userfaultfd_syscall_allowed() passes an unprivileged caller only
 * for a user-mode-only fd.  The flag arrived in 5.11, so a kernel
 * that rejects it with EINVAL is retried without it, on each
 * transport in turn: the syscall first, then /dev/userfaultfd.
 * @flags carries only the O_CLOEXEC / O_NONBLOCK bits.  Returns the
 * fd, or -1 with errno set from the last attempt.
 */
int create_userfaultfd(unsigned int flags)
{
	int fd;

	fd = userfaultfd_create(flags | UFFD_USER_MODE_ONLY);
	if (fd < 0 && errno == EINVAL)
		fd = userfaultfd_create(flags);
	if (fd >= 0)
		return fd;

	fd = devuserfaultfd_create(flags | UFFD_USER_MODE_ONLY);
	if (fd < 0 && errno == EINVAL)
		fd = devuserfaultfd_create(flags);
	return fd;
}

static void userfaultfd_dump(struct object *obj, enum obj_scope scope)
{
	struct userfaultobj *uo = &obj->userfaultobj;

	output(2, "userfault fd:%d flags:%x scope:%d\n", uo->fd, uo->flags, scope);
}

/* One UFFDIO_API handshake asking for @features. */
static int uffd_handshake(int fd, __u64 features)
{
	struct uffdio_api api;

	memset(&api, 0, sizeof(api));
	api.api = UFFD_API;
	api.features = features;
	return ioctl(fd, UFFDIO_API, &api);
}

/*
 * Perform the UFFDIO_API handshake so the kernel accepts subsequent
 * userfaultfd ioctls (UFFDIO_REGISTER, UFFDIO_COPY, etc.) on this fd.
 * Without the handshake, all other ioctls return -EINVAL.
 *
 * UFFD_FEATURE_SIGBUS is always on.  Nothing reads these fds, so a
 * fault on a range one of them registered would otherwise sleep in
 * handle_userfault() until the parent's watchdog killed the child:
 * the child's own store to a MISSING-registered fuzz map, say.  With
 * it every such fault is answered VM_FAULT_SIGBUS; the fault
 * injectors' guard recovers a store, and a kernel copy gets EFAULT.
 * The kernel arms an fd once, with the first handshake that succeeds,
 * so one refused for the RWP bits, which kernels before 7.3 lack, goes
 * again without them, one refused for another feature retries with
 * SIGBUS alone, and an fd none arms must not be pooled, where a fuzzed
 * UFFDIO_API could arm it without SIGBUS.
 */
static bool arm_userfaultfd(int fd)
{
	static const __u64 feature_flags[] = {
		/*
		 * EVENT_* notification features (FORK/REMAP/REMOVE/UNMAP) are
		 * deliberately omitted.  Each makes its triggering mm operation
		 * (fork / mremap / madvise / munmap) block in
		 * userfaultfd_event_wait_completion until a monitor read()s the
		 * event -- and trinity runs no uffd monitor.  With EVENT_FORK set
		 * on these child-owned pool fds, the child's own fork()
		 * wedges forever with no reader.  Only enable these
		 * alongside a thread that drains the uffd.
		 */
		UFFD_FEATURE_PAGEFAULT_FLAG_WP,
		UFFD_FEATURE_MISSING_HUGETLBFS,
		UFFD_FEATURE_MISSING_SHMEM,
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
	__u64 features = UFFD_FEATURE_SIGBUS, rwp = 0;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(feature_flags); i++) {
		if (rnd_u32() & 1)
			features |= feature_flags[i];
	}
	/* RWP lets UFFDIO_REGISTER take MODE_RWP, and RWP_ASYNC, which the
	 * kernel refuses without it, lets UFFDIO_SET_MODE run.  A fault on
	 * a read-write-protected range still meets SIGBUS. */
	if (RAND_BOOL()) {
		rwp = UFFD_FEATURE_RWP;
		if (RAND_BOOL())
			rwp |= UFFD_FEATURE_RWP_ASYNC;
	}

	if (uffd_handshake(fd, features | rwp) == 0)
		return true;
	if (rwp != 0 && errno == EINVAL && uffd_handshake(fd, features) == 0)
		return true;
	return uffd_handshake(fd, UFFD_FEATURE_SIGBUS) == 0;
}

/*
 * Create and arm one userfaultfd in the calling process and publish it
 * into its OBJ_LOCAL pool.  The kernel binds a uffd to its creator's
 * mm, so a uffd made by the parent acts on the parent's address space
 * from every child that inherits it; only a per-child uffd registers,
 * copies and write-protects the child's own ranges.
 */
static void open_userfaultfd(void)
{
	struct object *obj;
	int fd, flags;

	flags = RAND_BOOL() ? O_NONBLOCK : 0;
	if (RAND_BOOL())
		flags |= O_CLOEXEC;

	fd = create_userfaultfd(flags);

	if (fd < 0)
		return;

	if (!arm_userfaultfd(fd)) {
		close(fd);
		return;
	}

	obj = alloc_object();
	if (obj == NULL) {
		close(fd);
		return;
	}
	obj->userfaultobj.fd = fd;
	obj->userfaultobj.flags = flags;
	add_object(obj, OBJ_LOCAL, OBJ_FD_USERFAULTFD);
}

/*
 * Parent-side setup: wire the OBJ_GLOBAL head's destroy + dump slots so
 * init_object_lists(OBJ_LOCAL, child) inherits them into every child's
 * per-pool objhead, and probe that a userfaultfd can be created at all
 * through create_userfaultfd(), the user-mode-only path children use.
 * The probe fd is closed at once, never published and never armed, so
 * it registers no range in any mm.  The OBJ_GLOBAL pool stays empty:
 * every uffd the pool holds is created per-child by
 * userfaultfd_child_init() into that child's private OBJ_LOCAL pool.
 */
static int init_userfaultfds(void)
{
	struct objhead *head;
	int fd;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_USERFAULTFD);
	head->destroy = &close_fd_destructor;
	head->dump = &userfaultfd_dump;

	fd = create_userfaultfd(0);
	if (fd < 0) {
		int err = errno;
		enum fd_init_reason reason = (err == ENOSYS || err == ENXIO ||
					      err == ENODEV || err == ENOENT) ?
				FD_INIT_REASON_CONFIG_ABSENT :
				(err == EACCES || err == EPERM) ?
				FD_INIT_REASON_CAP_MISSING :
				FD_INIT_REASON_ERRNO;
		fd_provider_init_fail(reason, err, "userfaultfd_create");
		return false;
	}
	close(fd);
	return true;
}

/*
 * Per-child seed: create the pool's uffds in the calling child's own
 * mm, after the sandbox is in effect.  Creation can still fail there
 * (a pre-5.11 kernel with vm.unprivileged_userfaultfd=0, a seccomp
 * filter, or fd exhaustion); a child with no uffd simply draws none,
 * as it did when the fuzzed userfaultfd() call failed.
 */
static void userfaultfd_child_init(struct childdata *child __attribute__((unused)))
{
	unsigned int i;

	for (i = 0; i < 4; i++)
		open_userfaultfd();
}

/*
 * Per-child (OBJ_LOCAL) picker.  Every uffd tracked as an object
 * lives in the calling child's OBJ_LOCAL pool -- seeded by
 * userfaultfd_child_init() or published there by the userfaultfd()
 * post handler -- and not exposed to the OBJ_GLOBAL lockless-reader
 * UAF window (single-writer / single-reader inside one child).  The
 * objpool_check() and retry cap match the shape the other per-child
 * pickers use.
 */
static int get_rand_userfaultfd(void)
{
	if (objects_pool_empty(OBJ_LOCAL, OBJ_FD_USERFAULTFD) == true)
		return -1;

	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_USERFAULTFD, OBJ_LOCAL);
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
	.child_init = &userfaultfd_child_init,
	/*
	 * uffd_poll() blocks until the kernel has a pending page-fault event
	 * to deliver; with no registered VMA / no fault driver, EPOLL_CTL_ADD
	 * → ep_item_poll wedges the caller in TASK_UNINTERRUPTIBLE.  Bar from
	 * watch sets; direct read()/UFFDIO_* fuzzing remains unaffected.
	 */
	.poll_can_block = true,
};

REG_FD_PROV(userfaultfd_provider);
