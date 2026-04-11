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

static void iommufd_destructor(struct object *obj)
{
	close(obj->iommufdobj.fd);
}

static void iommufd_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "iommufd fd:%d scope:%d\n", obj->iommufdobj.fd, scope);
}

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
	head->destroy = &iommufd_destructor;
	head->dump = &iommufd_dump;

	fd = open_iommufd();
	if (fd < 0)
		return false;

	obj = alloc_object();
	obj->iommufdobj.fd = fd;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_IOMMUFD);
	return true;
}

static int get_rand_iommufd_fd(void)
{
	struct object *obj;

	if (objects_empty(OBJ_FD_IOMMUFD) == true)
		return -1;

	obj = get_random_object(OBJ_FD_IOMMUFD, OBJ_GLOBAL);
	if (obj == NULL)
		return -1;
	return obj->iommufdobj.fd;
}

static int open_iommufd_fd(void)
{
	struct object *obj;
	int fd;

	fd = open_iommufd();
	if (fd < 0)
		return false;

	obj = alloc_object();
	obj->iommufdobj.fd = fd;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_IOMMUFD);
	return true;
}

static const struct fd_provider iommufd_fd_provider = {
	.name = "iommufd",
	.objtype = OBJ_FD_IOMMUFD,
	.enabled = true,
	.init = &init_iommufd_fds,
	.get = &get_rand_iommufd_fd,
	.open = &open_iommufd_fd,
};

REG_FD_PROV(iommufd_fd_provider);

#endif
