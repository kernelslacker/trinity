/* epoll ioctl fuzzing */

#include <linux/ioctl.h>
#include <linux/types.h>
#include <sys/stat.h>

#include "ioctls.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

static int epoll_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;

	head = &shm->global_objects[OBJ_FD_EPOLL];

	for_each_obj(head, obj, idx) {
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

static void epoll_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	struct epoll_params *params;

	pick_random_ioctl(grp, rec);

	params = (struct epoll_params *) get_writable_struct(sizeof(*params));
	if (!params)
		return;

	if (rec->a2 == EPIOCSPARAMS) {
		params->busy_poll_usecs = rand() % 1000000;
		params->busy_poll_budget = rand() % 256;
		params->prefer_busy_poll = RAND_BOOL();
		params->__pad = 0;
	}

	rec->a3 = (unsigned long) params;
}

static const struct ioctl epoll_ioctls[] = {
	IOCTL(EPIOCSPARAMS),
	IOCTL(EPIOCGPARAMS),
};

static const struct ioctl_group epoll_grp = {
	.name = "epoll",
	.fd_test = epoll_fd_test,
	.sanitise = epoll_sanitise,
	.ioctls = epoll_ioctls,
	.ioctls_cnt = ARRAY_SIZE(epoll_ioctls),
};

REG_IOCTL_GROUP(epoll_grp)
