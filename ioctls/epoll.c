/* epoll ioctl fuzzing */

#include <linux/ioctl.h>
#include <linux/types.h>
#include <sys/stat.h>

#include "ioctls.h"
#include "kernel/epoll.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

static int epoll_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_EPOLL);

	for_each_obj(head, obj, idx) {
		if (obj->epollobj.fd == fd)
			return 0;
	}

	/* The child's own: see fd_class in ioctls.h. */
	if (find_local_object_by_fd(OBJ_FD_EPOLL, fd) != NULL)
		return 0;

	return -1;
}

/*
 * Compile-time: EPIOCSPARAMS and EPIOCGPARAMS both carry struct
 * epoll_params and the sanitiser below fills it to sizeof(struct).
 * Pin each direction against its _IOC_SIZE independently so a
 * <linux/eventpoll.h> change that grows or shrinks the struct
 * (or -- more likely -- the older-header fallback in kernel/epoll.h
 * drifting from the shipping uapi) hard-fails the compile rather than
 * silently letting the kernel copy_from_user() / copy_to_user() a
 * different number of bytes than the sanitiser prepared.  The two
 * directions get one assert each: a header refactor could
 * conceivably touch one _IOC_SIZE and not the other.
 */
IOCTL_SIZE_ASSERT(EPIOCSPARAMS, struct epoll_params);
IOCTL_SIZE_ASSERT(EPIOCGPARAMS, struct epoll_params);

static void epoll_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	struct epoll_params *params;

	pick_random_ioctl(grp, rec);

	params = (struct epoll_params *) get_writable_struct(sizeof(*params));
	if (!params)
		return;
	memset(params, 0, sizeof(*params));

	if (rec->a2 == EPIOCSPARAMS) {
		params->busy_poll_usecs = rnd_modulo_u32(1000000);
		/* A budget past NAPI_POLL_WEIGHT (64) is -EPERM without
		 * CAP_NET_ADMIN, which no child holds: one draw in eight
		 * goes past it, for that refusal. */
		params->busy_poll_budget = ONE_IN(8) ? 65 + rnd_modulo_u32(191) :
						       rnd_modulo_u32(65);
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
	.fd_class = ARG_FD_EPOLL,
	.sanitise = epoll_sanitise,
	.ioctls = epoll_ioctls,
	.ioctls_cnt = ARRAY_SIZE(epoll_ioctls),
};

REG_IOCTL_GROUP(epoll_grp)
