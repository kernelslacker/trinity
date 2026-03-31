#include <linux/ioctl.h>
#include <linux/seccomp.h>

#include "ioctls.h"
#include "utils.h"

/*
 * Seccomp notification listener ioctls.  These operate on the anonymous fd
 * returned by seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, ...).
 * There is no device node to match against, so this group is only reachable
 * via get_random_ioctl_group().
 */
static const struct ioctl seccomp_notif_ioctls[] = {
	IOCTL(SECCOMP_IOCTL_NOTIF_RECV),
	IOCTL(SECCOMP_IOCTL_NOTIF_SEND),
	IOCTL(SECCOMP_IOCTL_NOTIF_ID_VALID),
	IOCTL(SECCOMP_IOCTL_NOTIF_ADDFD),
	IOCTL(SECCOMP_IOCTL_NOTIF_SET_FLAGS),
};

static const struct ioctl_group seccomp_notif_grp = {
	.name = "seccomp-notif",
	.sanitise = pick_random_ioctl,
	.ioctls = seccomp_notif_ioctls,
	.ioctls_cnt = ARRAY_SIZE(seccomp_notif_ioctls),
};

REG_IOCTL_GROUP(seccomp_notif_grp)
