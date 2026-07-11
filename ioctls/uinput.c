#include <linux/ioctl.h>
#include <linux/uinput.h>

#include "utils.h"
#include "ioctls.h"

/*
 * Compile-time: every fixed-shape uinput ioctl command in the table
 * below whose arg is a kernel struct must have sizeof(struct)
 * matching the _IOC_SIZE encoded in its request bits.  A mismatch
 * means uinput.h moved under us and the request bits now encode a
 * different struct than we're passing (or vice versa) -- either
 * short of the kernel's copy_from_user() / copy_to_user() or past
 * it.  UI_BEGIN_FF_UPLOAD and UI_END_FF_UPLOAD both take
 * uinput_ff_upload, and UI_BEGIN_FF_ERASE and UI_END_FF_ERASE both
 * take uinput_ff_erase; each command gets its own assert -- the
 * sides can drift independently in a header refactor.
 *
 * UI_DEV_CREATE and UI_DEV_DESTROY are _IO() with no arg;
 * UI_SET_EVBIT, UI_SET_KEYBIT, UI_SET_RELBIT, UI_SET_ABSBIT,
 * UI_SET_MSCBIT, UI_SET_LEDBIT, UI_SET_SNDBIT, UI_SET_FFBIT,
 * UI_SET_SWBIT and UI_SET_PROPBIT encode a bare int; UI_SET_PHYS
 * encodes a char *.  All are intentionally absent -- asserting
 * sizeof(struct) against a scalar or a zero _IOC_SIZE would be the
 * wrong shape of check.
 */
IOCTL_SIZE_ASSERT(UI_BEGIN_FF_UPLOAD, struct uinput_ff_upload);
IOCTL_SIZE_ASSERT(UI_END_FF_UPLOAD, struct uinput_ff_upload);
IOCTL_SIZE_ASSERT(UI_BEGIN_FF_ERASE, struct uinput_ff_erase);
IOCTL_SIZE_ASSERT(UI_END_FF_ERASE, struct uinput_ff_erase);

static const struct ioctl uinput_ioctls[] = {
	IOCTL(UI_DEV_CREATE),
	IOCTL(UI_DEV_DESTROY),
	IOCTL(UI_SET_EVBIT),
	IOCTL(UI_SET_KEYBIT),
	IOCTL(UI_SET_RELBIT),
	IOCTL(UI_SET_ABSBIT),
	IOCTL(UI_SET_MSCBIT),
	IOCTL(UI_SET_LEDBIT),
	IOCTL(UI_SET_SNDBIT),
	IOCTL(UI_SET_FFBIT),
	IOCTL(UI_SET_PHYS),
	IOCTL(UI_SET_SWBIT),
#ifdef UI_SET_PROPBIT
	IOCTL(UI_SET_PROPBIT),
#endif
	IOCTL(UI_BEGIN_FF_UPLOAD),
	IOCTL(UI_END_FF_UPLOAD),
	IOCTL(UI_BEGIN_FF_ERASE),
	IOCTL(UI_END_FF_ERASE),
};

static const char *const uinput_devs[] = {
	"uinput",
};

static const struct ioctl_group uinput_grp = {
	.devtype = DEV_MISC,
	.devs = uinput_devs,
	.devs_cnt = ARRAY_SIZE(uinput_devs),
	.sanitise = pick_random_ioctl,
	.ioctls = uinput_ioctls,
	.ioctls_cnt = ARRAY_SIZE(uinput_ioctls),
};

REG_IOCTL_GROUP(uinput_grp)
