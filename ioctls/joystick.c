/* jsdev (/dev/input/jsN) ioctl fuzzing */

#include <linux/ioctl.h>
#include <linux/joystick.h>
#include <linux/major.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "ioctls.h"
#include "random.h"
#include "shm.h"
#include "syscall.h"
#include "utils.h"

/*
 * jsdev shares INPUT_MAJOR (13) with evdev, so a devname-only match
 * collides with the input group.  Use fd_test to claim only the
 * jsdev minor range; evdev (minor >= 64) falls through to input.c.
 */
#define JOYDEV_MINORS	32

static const struct ioctl joystick_ioctls[] = {
#ifdef JSIOCGVERSION
	IOCTL(JSIOCGVERSION),
#endif
#ifdef JSIOCGAXES
	IOCTL(JSIOCGAXES),
#endif
#ifdef JSIOCGBUTTONS
	IOCTL(JSIOCGBUTTONS),
#endif
#ifdef JSIOCGNAME
	IOCTL(JSIOCGNAME(0)),
#endif
#ifdef JSIOCSCORR
	IOCTL(JSIOCSCORR),
#endif
#ifdef JSIOCGCORR
	IOCTL(JSIOCGCORR),
#endif
#ifdef JSIOCSAXMAP
	IOCTL(JSIOCSAXMAP),
#endif
#ifdef JSIOCGAXMAP
	IOCTL(JSIOCGAXMAP),
#endif
#ifdef JSIOCSBTNMAP
	IOCTL(JSIOCSBTNMAP),
#endif
#ifdef JSIOCGBTNMAP
	IOCTL(JSIOCGBTNMAP),
#endif
};

static int joystick_fd_test(int fd __attribute__((unused)),
			    const struct stat *st)
{
	if (!S_ISCHR(st->st_mode))
		return -1;
	if (major(st->st_rdev) != INPUT_MAJOR)
		return -1;
	if (minor(st->st_rdev) >= JOYDEV_MINORS)
		return -1;
	return 0;
}

/*
 * JSIOCGNAME encodes a userspace-chosen length in the _IOC_SIZE field;
 * the table entry carries length 0, so rewrite a2 with a random length
 * to actually exercise the kernel's size-handling path.
 */
static void joystick_sanitise(const struct ioctl_group *grp,
			      struct syscallrecord *rec)
{
	unsigned int u;

	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
#ifdef JSIOCGNAME
	case JSIOCGNAME(0):
		u = rand();
		rec->a2 = JSIOCGNAME(u);
		break;
#endif
	default:
		break;
	}
}

static const char *const joystick_devs[] = {
	"input",
};

static const struct ioctl_group joystick_grp = {
	.name = "joystick",
	.devtype = DEV_CHAR,
	.devs = joystick_devs,
	.devs_cnt = ARRAY_SIZE(joystick_devs),
	.fd_test = joystick_fd_test,
	.sanitise = joystick_sanitise,
	.ioctls = joystick_ioctls,
	.ioctls_cnt = ARRAY_SIZE(joystick_ioctls),
};

REG_IOCTL_GROUP(joystick_grp)
