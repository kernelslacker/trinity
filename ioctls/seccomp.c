#ifdef USE_SECCOMP

#include <linux/ioctl.h>
#include <linux/seccomp.h>

#include "ioctls.h"
#include "objects.h"
#include "shm.h"
#include "utils.h"

/*
 * Seccomp notification listener ioctls.  These operate on the anonymous fd
 * returned by seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, ...).
 *
 * The fd_test matches against fds registered by the seccomp_notif fd provider,
 * so ioctl fuzzing is directed at the right file descriptors.
 */
static int seccomp_notif_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;

	head = &shm->global_objects[OBJ_FD_SECCOMP_NOTIF];

	for_each_obj(head, obj, idx) {
		if (obj->seccomp_notifobj.fd == fd)
			return 0;
	}

	return -1;
}

static const struct ioctl seccomp_notif_ioctls[] = {
	IOCTL(SECCOMP_IOCTL_NOTIF_RECV),
	IOCTL(SECCOMP_IOCTL_NOTIF_SEND),
	IOCTL(SECCOMP_IOCTL_NOTIF_ID_VALID),
	IOCTL(SECCOMP_IOCTL_NOTIF_ADDFD),
	IOCTL(SECCOMP_IOCTL_NOTIF_SET_FLAGS),
};

static const struct ioctl_group seccomp_notif_grp = {
	.name = "seccomp-notif",
	.fd_test = seccomp_notif_fd_test,
	.sanitise = pick_random_ioctl,
	.ioctls = seccomp_notif_ioctls,
	.ioctls_cnt = ARRAY_SIZE(seccomp_notif_ioctls),
};

REG_IOCTL_GROUP(seccomp_notif_grp)

#endif /* USE_SECCOMP */
