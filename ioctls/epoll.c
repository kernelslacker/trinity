/* epoll ioctl fuzzing */

#include <linux/ioctl.h>
#include <linux/types.h>
#include <sys/stat.h>

#include "ioctls.h"
#include "objects.h"
#include "shm.h"
#include "utils.h"

static int epoll_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct list_head *globallist, *node;
	struct object *obj;

	globallist = shm->global_objects[OBJ_FD_EPOLL].list;
	list_for_each(node, globallist) {
		obj = (struct object *) node;
		if (obj->epollobj.fd == fd)
			return 0;
	}

	return -1;
}

#ifndef EPIOCSPARAMS
struct epoll_params {
	__u32 busy_poll_usecs;
	__u16 busy_poll_budget;
	__u8 prefer_busy_poll;
	__u8 __pad;
};
#define EPOLL_IOC_TYPE 0x8A
#define EPIOCSPARAMS _IOW(EPOLL_IOC_TYPE, 0x01, struct epoll_params)
#define EPIOCGPARAMS _IOR(EPOLL_IOC_TYPE, 0x02, struct epoll_params)
#endif

static const struct ioctl epoll_ioctls[] = {
	IOCTL(EPIOCSPARAMS),
	IOCTL(EPIOCGPARAMS),
};

static const struct ioctl_group epoll_grp = {
	.name = "epoll",
	.fd_test = epoll_fd_test,
	.sanitise = pick_random_ioctl,
	.ioctls = epoll_ioctls,
	.ioctls_cnt = ARRAY_SIZE(epoll_ioctls),
};

REG_IOCTL_GROUP(epoll_grp)
