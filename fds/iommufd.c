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
	 * iommufdobj is {int fd;} with no pointer members, so the
	 * OBJ_GLOBAL pool's scalars stay valid across fork/COW and
	 * cross-process reads are safe.
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
	 * obj->iommufdobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the iommufd handed to ioctl(IOMMU_*) via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
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
