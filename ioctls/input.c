#include <linux/ioctl.h>
#include <linux/input.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "syscall.h"
#include "utils.h"

/*
 * Compile-time: every fixed-shape input ioctl command in the table
 * below whose arg is a kernel struct must have sizeof(struct)
 * matching the _IOC_SIZE encoded in its request bits.  A mismatch
 * means input.h moved under us and the request bits now encode a
 * different struct than we're passing (or vice versa) -- either
 * short of the kernel's copy_from_user() / copy_to_user() or past
 * it.  Commands sharing a struct (EVIOCGKEYCODE_V2 and
 * EVIOCSKEYCODE_V2 both take input_keymap_entry; EVIOCGABS and
 * EVIOCSABS both take input_absinfo; EVIOCGMASK and EVIOCSMASK both
 * take input_mask) get one assert each -- the two sides can drift
 * independently in a header refactor.  Per-cmd #ifdef guards mirror
 * the ioctl-table wrapping so builds against older uapi headers
 * that predate a command still compile.
 *
 * EVIOCGREP, EVIOCSREP, EVIOCGKEYCODE and EVIOCSKEYCODE encode a
 * bare unsigned int[2] pair; the EVIOCG*(len) family (GNAME, GPHYS,
 * GUNIQ, GPROP, GMTSLOTS, GKEY, GLED, GSND, GSW, GBIT) encode the
 * buffer length in the request bits and take a variable-length
 * buffer; EVIOCGVERSION, EVIOCGEFFECTS and EVIOCSCLOCKID encode a
 * bare int, and EVIOCRMFF encodes a bare int effect id;
 * EVIOCGRAB and EVIOCREVOKE are _IOW(int) / _IO() with no struct
 * arg.  All are intentionally absent -- asserting sizeof(struct)
 * against a scalar, a fixed-size array pair, or a length-encoded
 * variable buffer would be the wrong shape of check.
 */
_Static_assert(sizeof(struct input_id) ==
	       _IOC_SIZE(EVIOCGID),
	       "input_id size vs _IOC_SIZE mismatch");
#ifdef EVIOCGKEYCODE_V2
_Static_assert(sizeof(struct input_keymap_entry) ==
	       _IOC_SIZE(EVIOCGKEYCODE_V2),
	       "input_keymap_entry size vs EVIOCGKEYCODE_V2 mismatch");
#endif
#ifdef EVIOCSKEYCODE_V2
_Static_assert(sizeof(struct input_keymap_entry) ==
	       _IOC_SIZE(EVIOCSKEYCODE_V2),
	       "input_keymap_entry size vs EVIOCSKEYCODE_V2 mismatch");
#endif
_Static_assert(sizeof(struct input_absinfo) ==
	       _IOC_SIZE(EVIOCGABS(0)),
	       "input_absinfo size vs EVIOCGABS mismatch");
_Static_assert(sizeof(struct input_absinfo) ==
	       _IOC_SIZE(EVIOCSABS(0)),
	       "input_absinfo size vs EVIOCSABS mismatch");
_Static_assert(sizeof(struct ff_effect) ==
	       _IOC_SIZE(EVIOCSFF),
	       "ff_effect size vs _IOC_SIZE mismatch");
#ifdef EVIOCGMASK
_Static_assert(sizeof(struct input_mask) ==
	       _IOC_SIZE(EVIOCGMASK),
	       "input_mask size vs EVIOCGMASK mismatch");
#endif
#ifdef EVIOCSMASK
_Static_assert(sizeof(struct input_mask) ==
	       _IOC_SIZE(EVIOCSMASK),
	       "input_mask size vs EVIOCSMASK mismatch");
#endif

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
#ifdef EVIOCREVOKE
	IOCTL(EVIOCREVOKE),
#endif
#ifdef EVIOCGMASK
	IOCTL(EVIOCGMASK),
#endif
#ifdef EVIOCSMASK
	IOCTL(EVIOCSMASK),
#endif
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
		u = rnd_u32();
		rec->a2 = EVIOCGNAME(u);
		break;
	case EVIOCGPHYS(0):
		u = rnd_u32();
		rec->a2 = EVIOCGPHYS(u);
		break;
	case EVIOCGUNIQ(0):
		u = rnd_u32();
		rec->a2 = EVIOCGUNIQ(u);
		break;
#ifdef EVIOCGPROP
	case EVIOCGPROP(0):
		u = rnd_u32();
		rec->a2 = EVIOCGPROP(u);
		break;
#endif
#ifdef EVIOCGMTSLOTS
	case EVIOCGMTSLOTS(0):
		u = rnd_u32();
		rec->a2 = EVIOCGMTSLOTS(u);
		break;
#endif
	case EVIOCGKEY(0):
		u = rnd_u32();
		rec->a2 = EVIOCGKEY(u);
		break;
	case EVIOCGLED(0):
		u = rnd_u32();
		rec->a2 = EVIOCGLED(u);
		break;
	case EVIOCGSND(0):
		u = rnd_u32();
		rec->a2 = EVIOCGSND(u);
		break;
	case EVIOCGSW(0):
		u = rnd_u32();
		rec->a2 = EVIOCGSW(u);
		break;
	case EVIOCGBIT(0,0):
		u = rnd_u32();
		r = rnd_u32();
		if (u % 10) u %= EV_CNT;
		if (r % 10) r /= 4;
		rec->a2 = EVIOCGBIT(u, r);
		break;
	case EVIOCGABS(0):
		u = rnd_u32();
		if (u % 10) u %= ABS_CNT;
		rec->a2 = EVIOCGABS(u);
		break;
	case EVIOCSABS(0):
		u = rnd_u32();
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
