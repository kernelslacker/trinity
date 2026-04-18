#include <glob.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/ioctl.h>
#include <linux/loop.h>

#include "utils.h"
#include "ioctls.h"

static const struct ioctl loop_dev_ioctls[] = {
	IOCTL(LOOP_SET_FD),
	IOCTL(LOOP_CLR_FD),
	IOCTL(LOOP_SET_STATUS),
	IOCTL(LOOP_GET_STATUS),
	IOCTL(LOOP_SET_STATUS64),
	IOCTL(LOOP_GET_STATUS64),
	IOCTL(LOOP_CHANGE_FD),
	IOCTL(LOOP_SET_CAPACITY),
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
	.devtype = DEV_MISC,
	.devs = loop_ctrl_devs,
	.devs_cnt = ARRAY_SIZE(loop_ctrl_devs),
	.sanitise = pick_random_ioctl,
	.ioctls = loop_ctrl_ioctls,
	.ioctls_cnt = ARRAY_SIZE(loop_ctrl_ioctls),
};

REG_IOCTL_GROUP(loop_ctrl_grp)

/* Discovered loop block devices from glob("/dev/loop*"). */
static dev_t *loop_rdevs;
static size_t nr_loop_rdevs;

static void __attribute__((constructor)) discover_loop_block_devs(void)
{
	glob_t g;
	struct stat st;
	size_t i;

	if (glob("/dev/loop[0-9]*", 0, NULL, &g) != 0)
		return;

	loop_rdevs = malloc(g.gl_pathc * sizeof(dev_t));
	if (!loop_rdevs) {
		globfree(&g);
		return;
	}

	for (i = 0; i < g.gl_pathc; i++) {
		if (stat(g.gl_pathv[i], &st) == 0 && S_ISBLK(st.st_mode))
			loop_rdevs[nr_loop_rdevs++] = st.st_rdev;
	}

	globfree(&g);
}

static int loop_fd_test(int fd __attribute__((unused)), const struct stat *st)
{
	size_t i;

	if (!S_ISBLK(st->st_mode))
		return -1;

	for (i = 0; i < nr_loop_rdevs; i++) {
		if (loop_rdevs[i] == st->st_rdev)
			return 0;
	}

	return -1;
}

static const struct ioctl_group loop_grp = {
	.fd_test = loop_fd_test,
	.sanitise = pick_random_ioctl,
	.ioctls = loop_dev_ioctls,
	.ioctls_cnt = ARRAY_SIZE(loop_dev_ioctls),
};

REG_IOCTL_GROUP(loop_grp)
