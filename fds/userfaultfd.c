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
static int devuserfaultfd_create(void)
{
	int devfd, fd;

	devfd = open("/dev/userfaultfd", O_RDWR | O_CLOEXEC);
	if (devfd < 0)
		return -1;

	fd = ioctl(devfd, USERFAULTFD_IOC_NEW, NULL);
	close(devfd);
	return fd;
}

static void userfaultfd_destructor(struct object *obj)
{
	close(obj->userfaultobj.fd);
}

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
		fd = devuserfaultfd_create();
	else
		fd = userfaultfd_create(flags);

	if (fd < 0)
		return false;

	arm_userfaultfd(fd);

	obj = alloc_object();
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

	for (i = 0; i < 4; i++) {
		if (open_userfaultfd())
			ret = true;
	}

	return ret;
}

static int get_rand_userfaultfd(void)
{
	struct object *obj;

	/* check if userfaultfd unavailable/disabled. */
	if (objects_empty(OBJ_FD_USERFAULTFD) == true)
		return -1;

	obj = get_random_object(OBJ_FD_USERFAULTFD, OBJ_GLOBAL);
	if (obj == NULL)
		return -1;
	return obj->userfaultobj.fd;
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
