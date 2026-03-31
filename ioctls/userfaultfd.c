/* userfaultfd ioctl fuzzing */

#include <linux/ioctl.h>
#include <linux/userfaultfd.h>

#include "ioctls.h"
#include "objects.h"
#include "shm.h"
#include "utils.h"

static int userfaultfd_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct list_head *globallist, *node;
	struct object *obj;

	globallist = shm->global_objects[OBJ_FD_USERFAULTFD].list;
	list_for_each(node, globallist) {
		obj = (struct object *) node;
		if (obj->userfaultobj.fd == fd)
			return 0;
	}

	return -1;
}

static const struct ioctl userfaultfd_ioctls[] = {
	IOCTL(UFFDIO_API),
	IOCTL(UFFDIO_REGISTER),
	IOCTL(UFFDIO_UNREGISTER),
	IOCTL(UFFDIO_WAKE),
	IOCTL(UFFDIO_COPY),
	IOCTL(UFFDIO_ZEROPAGE),
	IOCTL(UFFDIO_WRITEPROTECT),
	IOCTL(UFFDIO_CONTINUE),
	IOCTL(UFFDIO_POISON),
	IOCTL(UFFDIO_MOVE),
};

static const struct ioctl_group userfaultfd_grp = {
	.name = "userfaultfd",
	.fd_test = userfaultfd_fd_test,
	.sanitise = pick_random_ioctl,
	.ioctls = userfaultfd_ioctls,
	.ioctls_cnt = ARRAY_SIZE(userfaultfd_ioctls),
};

REG_IOCTL_GROUP(userfaultfd_grp)
