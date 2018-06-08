#include <linux/ioctl.h>
#include <linux/input.h>

#include "ioctls.h"
#include "random.h"
#include "shm.h"
#include "syscall.h"
#include "utils.h"

static const struct ioctl input_ioctls[] = {
	IOCTL(EVIOCGVERSION),
	IOCTL(EVIOCGID),
	IOCTL(EVIOCGREP),
	IOCTL(EVIOCSREP),
	IOCTL(EVIOCGKEYCODE),
#ifdef EVIOCGKEYCODE_V2
	IOCTL(EVIOCGKEYCODE_V2),
#endif
	IOCTL(EVIOCSKEYCODE),
#ifdef EVIOCSKEYCODE_V2
	IOCTL(EVIOCSKEYCODE_V2),
#endif
	IOCTL(EVIOCGNAME(0)),
	IOCTL(EVIOCGPHYS(0)),
	IOCTL(EVIOCGUNIQ(0)),
#ifdef EVIOCGPROP
	IOCTL(EVIOCGPROP(0)),
#endif
#ifdef EVIOCGMTSLOTS
	IOCTL(EVIOCGMTSLOTS(0)),
#endif
	IOCTL(EVIOCGKEY(0)),
	IOCTL(EVIOCGLED(0)),
	IOCTL(EVIOCGSND(0)),
	IOCTL(EVIOCGSW(0)),
	IOCTL(EVIOCGBIT(0,0)),
	IOCTL(EVIOCGABS(0)),
	IOCTL(EVIOCSABS(0)),
	IOCTL(EVIOCSFF),
	IOCTL(EVIOCRMFF),
	IOCTL(EVIOCGEFFECTS),
	IOCTL(EVIOCGRAB),
#ifdef EVIOCSCLOCKID
	IOCTL(EVIOCSCLOCKID),
#endif
};

static const char *const input_devs[] = {
	"input",
};

static void input_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	unsigned int u, r;

	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case EVIOCGNAME(0):
		u = rnd();
		rec->a2 = EVIOCGNAME(u);
		break;
	case EVIOCGPHYS(0):
		u = rnd();
		rec->a2 = EVIOCGPHYS(u);
		break;
	case EVIOCGUNIQ(0):
		u = rnd();
		rec->a2 = EVIOCGUNIQ(u);
		break;
#ifdef EVIOCGPROP
	case EVIOCGPROP(0):
		u = rnd();
		rec->a2 = EVIOCGPROP(u);
		break;
#endif
#ifdef EVIOCGMTSLOTS
	case EVIOCGMTSLOTS(0):
		u = rnd();
		rec->a2 = EVIOCGMTSLOTS(u);
		break;
#endif
	case EVIOCGKEY(0):
		u = rnd();
		rec->a2 = EVIOCGKEY(u);
		break;
	case EVIOCGLED(0):
		u = rnd();
		rec->a2 = EVIOCGLED(u);
		break;
	case EVIOCGSND(0):
		u = rnd();
		rec->a2 = EVIOCGSND(u);
		break;
	case EVIOCGSW(0):
		u = rnd();
		rec->a2 = EVIOCGSW(u);
		break;
	case EVIOCGBIT(0,0):
		u = rnd();
		r = rnd();
		if (u % 10) u %= EV_CNT;
		if (r % 10) r /= 4;
		rec->a2 = EVIOCGBIT(u, r);
		break;
	case EVIOCGABS(0):
		u = rnd();
		if (u % 10) u %= ABS_CNT;
		rec->a2 = EVIOCGABS(u);
		break;
	case EVIOCSABS(0):
		u = rnd();
		if (u % 10) u %= ABS_CNT;
		rec->a2 = EVIOCSABS(u);
		break;
	default:
		break;
	}
}

static const struct ioctl_group input_grp = {
	.devtype = DEV_MISC,
	.devs = input_devs,
	.devs_cnt = ARRAY_SIZE(input_devs),
	.sanitise = input_sanitise,
	.ioctls = input_ioctls,
	.ioctls_cnt = ARRAY_SIZE(input_ioctls),
};

REG_IOCTL_GROUP(input_grp)
