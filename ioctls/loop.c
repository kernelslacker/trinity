/* /dev/loopN block device and /dev/loop-control ioctl fuzzing */

#include <linux/ioctl.h>
#include <linux/loop.h>
#include <linux/major.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "ioctls.h"
#include "utils.h"

/*
 * /dev/loopN block devices live on LOOP_MAJOR (7).  Match block fds by
 * major rather than by devname so we don't fire LOOP_* ioctls at other
 * block drivers that happen to share a name prefix.  /dev/loop-control
 * is a separate misc char device and gets its own group below.
 */

static const struct ioctl loop_dev_ioctls[] = {
#ifdef LOOP_SET_FD
	IOCTL(LOOP_SET_FD),
#endif
#ifdef LOOP_CLR_FD
	IOCTL(LOOP_CLR_FD),
#endif
#ifdef LOOP_SET_STATUS
	IOCTL(LOOP_SET_STATUS),
#endif
#ifdef LOOP_GET_STATUS
	IOCTL(LOOP_GET_STATUS),
#endif
#ifdef LOOP_SET_STATUS64
	IOCTL(LOOP_SET_STATUS64),
#endif
#ifdef LOOP_GET_STATUS64
	IOCTL(LOOP_GET_STATUS64),
#endif
#ifdef LOOP_CHANGE_FD
	IOCTL(LOOP_CHANGE_FD),
#endif
#ifdef LOOP_SET_CAPACITY
	IOCTL(LOOP_SET_CAPACITY),
#endif
#ifdef LOOP_SET_DIRECT_IO
	IOCTL(LOOP_SET_DIRECT_IO),
#endif
#ifdef LOOP_SET_BLOCK_SIZE
	IOCTL(LOOP_SET_BLOCK_SIZE),
#endif
#ifdef LOOP_CONFIGURE
	IOCTL(LOOP_CONFIGURE),
#endif
};

static const struct ioctl loop_ctrl_ioctls[] = {
#ifdef LOOP_CTL_ADD
	IOCTL(LOOP_CTL_ADD),
#endif
#ifdef LOOP_CTL_REMOVE
	IOCTL(LOOP_CTL_REMOVE),
#endif
#ifdef LOOP_CTL_GET_FREE
	IOCTL(LOOP_CTL_GET_FREE),
#endif
};

static const char *const loop_ctrl_devs[] = {
	"loop-control",
};

static const struct ioctl_group loop_ctrl_grp = {
	.name = "loop-control",
	.devtype = DEV_MISC,
	.devs = loop_ctrl_devs,
	.devs_cnt = ARRAY_SIZE(loop_ctrl_devs),
	.sanitise = pick_random_ioctl,
	.ioctls = loop_ctrl_ioctls,
	.ioctls_cnt = ARRAY_SIZE(loop_ctrl_ioctls),
};

REG_IOCTL_GROUP(loop_ctrl_grp)

static int loop_fd_test(int fd __attribute__((unused)),
			const struct stat *st)
{
	if (!S_ISBLK(st->st_mode))
		return -1;
	if (major(st->st_rdev) != LOOP_MAJOR)
		return -1;
	return 0;
}

static const char *const loop_devs[] = {
	"loop",
};

static const struct ioctl_group loop_grp = {
	.name = "loop",
	.devtype = DEV_BLOCK,
	.devs = loop_devs,
	.devs_cnt = ARRAY_SIZE(loop_devs),
	.fd_test = loop_fd_test,
	.sanitise = pick_random_ioctl,
	.ioctls = loop_dev_ioctls,
	.ioctls_cnt = ARRAY_SIZE(loop_dev_ioctls),
};

REG_IOCTL_GROUP(loop_grp)
