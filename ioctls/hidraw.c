/* hidraw ioctl fuzzing */

#include <linux/ioctl.h>
#include <linux/hidraw.h>

#include "ioctls.h"
#include "random.h"
#include "shm.h"
#include "syscall.h"
#include "utils.h"

/*
 * /dev/hidraw* are real character device nodes.  The hidraw driver
 * registers its own char-major and shows up in /proc/devices as
 * "hidraw", so the devtype/devs[] match path is reliable -- no
 * fd_test or anon_inode probe needed.
 */

static const struct ioctl hidraw_ioctls[] = {
#ifdef HIDIOCGRDESCSIZE
	IOCTL(HIDIOCGRDESCSIZE),
#endif
#ifdef HIDIOCGRDESC
	IOCTL(HIDIOCGRDESC),
#endif
#ifdef HIDIOCGRAWINFO
	IOCTL(HIDIOCGRAWINFO),
#endif
#ifdef HIDIOCGRAWNAME
	IOCTL(HIDIOCGRAWNAME(0)),
#endif
#ifdef HIDIOCGRAWPHYS
	IOCTL(HIDIOCGRAWPHYS(0)),
#endif
#ifdef HIDIOCSFEATURE
	IOCTL(HIDIOCSFEATURE(0)),
#endif
#ifdef HIDIOCGFEATURE
	IOCTL(HIDIOCGFEATURE(0)),
#endif
#ifdef HIDIOCGRAWUNIQ
	IOCTL(HIDIOCGRAWUNIQ(0)),
#endif
#ifdef HIDIOCSINPUT
	IOCTL(HIDIOCSINPUT(0)),
#endif
#ifdef HIDIOCGINPUT
	IOCTL(HIDIOCGINPUT(0)),
#endif
#ifdef HIDIOCSOUTPUT
	IOCTL(HIDIOCSOUTPUT(0)),
#endif
#ifdef HIDIOCGOUTPUT
	IOCTL(HIDIOCGOUTPUT(0)),
#endif
#ifdef HIDIOCREVOKE
	IOCTL(HIDIOCREVOKE),
#endif
};

static const char *const hidraw_devs[] = {
	"hidraw",
};

/*
 * The HIDIOC[GS]{RAWNAME,RAWPHYS,RAWUNIQ,FEATURE,INPUT,OUTPUT}
 * commands encode a userspace-chosen length in the _IOC_SIZE field of
 * the request.  Each entry above carries length 0; rewrite a2 with a
 * random length so the dispatched cmd actually exercises the kernel's
 * size handling instead of repeatedly hitting the len==0 path.
 */
static void hidraw_sanitise(const struct ioctl_group *grp,
			    struct syscallrecord *rec)
{
	unsigned int u;

	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
#ifdef HIDIOCGRAWNAME
	case HIDIOCGRAWNAME(0):
		u = rand();
		rec->a2 = HIDIOCGRAWNAME(u);
		break;
#endif
#ifdef HIDIOCGRAWPHYS
	case HIDIOCGRAWPHYS(0):
		u = rand();
		rec->a2 = HIDIOCGRAWPHYS(u);
		break;
#endif
#ifdef HIDIOCGRAWUNIQ
	case HIDIOCGRAWUNIQ(0):
		u = rand();
		rec->a2 = HIDIOCGRAWUNIQ(u);
		break;
#endif
#ifdef HIDIOCSFEATURE
	case HIDIOCSFEATURE(0):
		u = rand();
		rec->a2 = HIDIOCSFEATURE(u);
		break;
#endif
#ifdef HIDIOCGFEATURE
	case HIDIOCGFEATURE(0):
		u = rand();
		rec->a2 = HIDIOCGFEATURE(u);
		break;
#endif
#ifdef HIDIOCSINPUT
	case HIDIOCSINPUT(0):
		u = rand();
		rec->a2 = HIDIOCSINPUT(u);
		break;
#endif
#ifdef HIDIOCGINPUT
	case HIDIOCGINPUT(0):
		u = rand();
		rec->a2 = HIDIOCGINPUT(u);
		break;
#endif
#ifdef HIDIOCSOUTPUT
	case HIDIOCSOUTPUT(0):
		u = rand();
		rec->a2 = HIDIOCSOUTPUT(u);
		break;
#endif
#ifdef HIDIOCGOUTPUT
	case HIDIOCGOUTPUT(0):
		u = rand();
		rec->a2 = HIDIOCGOUTPUT(u);
		break;
#endif
	default:
		break;
	}
}

static const struct ioctl_group hidraw_grp = {
	.name = "hidraw",
	.devtype = DEV_CHAR,
	.devs = hidraw_devs,
	.devs_cnt = ARRAY_SIZE(hidraw_devs),
	.sanitise = hidraw_sanitise,
	.ioctls = hidraw_ioctls,
	.ioctls_cnt = ARRAY_SIZE(hidraw_ioctls),
};

REG_IOCTL_GROUP(hidraw_grp)
