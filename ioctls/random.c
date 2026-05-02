/* /dev/random and /dev/urandom ioctl fuzzing */

#include <linux/ioctl.h>
#include <linux/major.h>
#include <linux/random.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "ioctls.h"
#include "utils.h"

/*
 * /dev/random and /dev/urandom share MEM_MAJOR (1) with /dev/mem,
 * /dev/null, /dev/zero, /dev/full, /dev/port and /dev/kmsg.  A
 * devname-only match would hand all of those fds to this group, so
 * use fd_test to claim only the random/urandom minors.
 */
#define RANDOM_MINOR	8
#define URANDOM_MINOR	9

static const struct ioctl random_ioctls[] = {
#ifdef RNDGETENTCNT
	IOCTL(RNDGETENTCNT),
#endif
#ifdef RNDADDTOENTCNT
	IOCTL(RNDADDTOENTCNT),
#endif
#ifdef RNDGETPOOL
	IOCTL(RNDGETPOOL),
#endif
#ifdef RNDADDENTROPY
	IOCTL(RNDADDENTROPY),
#endif
#ifdef RNDZAPENTCNT
	IOCTL(RNDZAPENTCNT),
#endif
#ifdef RNDCLEARPOOL
	IOCTL(RNDCLEARPOOL),
#endif
#ifdef RNDRESEEDCRNG
	IOCTL(RNDRESEEDCRNG),
#endif
};

static int random_fd_test(int fd __attribute__((unused)),
			  const struct stat *st)
{
	if (!S_ISCHR(st->st_mode))
		return -1;
	if (major(st->st_rdev) != MEM_MAJOR)
		return -1;
	if (minor(st->st_rdev) != RANDOM_MINOR &&
	    minor(st->st_rdev) != URANDOM_MINOR)
		return -1;
	return 0;
}

static const char *const random_devs[] = {
	"mem",
};

static const struct ioctl_group random_grp = {
	.name = "random",
	.devtype = DEV_CHAR,
	.devs = random_devs,
	.devs_cnt = ARRAY_SIZE(random_devs),
	.fd_test = random_fd_test,
	.sanitise = pick_random_ioctl,
	.ioctls = random_ioctls,
	.ioctls_cnt = ARRAY_SIZE(random_ioctls),
};

REG_IOCTL_GROUP(random_grp)
