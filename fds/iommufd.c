/* IOMMUFD FD provider. */

#ifdef USE_IOMMUFD

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static int open_iommufd(void)
{
	int fd;

	fd = open("/dev/iommu", O_RDWR);
	if (fd < 0)
		return -1;
	return fd;
}

static int init_iommufd_fds(void)
{
	struct objhead *head;
	struct object *obj;
	int fd;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_IOMMUFD);
	head->destroy = &close_fd_destructor;
	head->dump = &generic_fd_dump;
	/*
	 * Opt this provider into the shared obj heap.  __destroy_object()
	 * checks this flag to route the obj struct release through
	 * free_shared_obj() instead of free().  iommufdobj is {int fd;}
	 * with no pointer members, so this is a mechanical conversion that
	 * matches the pidfd template exactly.
	 */

	fd = open_iommufd();
	if (fd < 0) {
		outputerr("init_iommufd_fds: open(/dev/iommu) failed: %s\n",
			strerror(errno));
		return false;
	}

	obj = alloc_object();
	if (obj == NULL) {
		outputerr("init_iommufd_fds: alloc_object failed\n");
		close(fd);
		return false;
	}
	obj->iommufdobj.fd = fd;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_IOMMUFD);
	return true;
}

static int get_rand_iommufd_fd(void)
{
	if (objects_empty(OBJ_FD_IOMMUFD) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->iommufdobj.fd deref, mirroring the wireup at 15b6257b8206
	 * (fds/sockets.c get_rand_socketinfo) and 5ef98298f6ad
	 * (syscalls/keyctl.c KEYCTL_WATCH_KEY).  Same OBJ_GLOBAL lockless-
	 * reader UAF window the framework commit a7fdbb97830c spelled out:
	 * between the lockless slot pick and the consumer's read of
	 * the iommufd handed to ioctl(IOMMU_*) via the fd_provider .get callback,
	 * the parent can destroy the obj, free_shared_obj() returns the
	 * chunk to the shared-heap freelist, and a concurrent
	 * alloc_object() recycles it underneath us.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_IOMMUFD, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_IOMMUFD))
			continue;

		fd = obj->iommufdobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider iommufd_fd_provider = {
	.name = "iommufd",
	.objtype = OBJ_FD_IOMMUFD,
	.enabled = true,
	.init = &init_iommufd_fds,
	.get = &get_rand_iommufd_fd,
};

REG_FD_PROV(iommufd_fd_provider);

#endif
