#include <linux/ioctl.h>
#include <linux/hpet.h>

#include "utils.h"
#include "ioctls.h"

/*
 * Compile-time: HPET_INFO is the only fixed-shape hpet ioctl.
 * sizeof(struct hpet_info) must match the _IOC_SIZE encoded in the
 * request bits, so a linux/hpet.h refactor that grows or shrinks
 * the struct hard-fails the compile instead of silently having the
 * kernel copy_to_user() a different number of bytes than we
 * prepared.  HPET_IE_ON, HPET_IE_OFF, HPET_EPI and HPET_DPI are
 * _IO() with no struct arg; HPET_IRQFREQ is _IOW(unsigned long), a
 * bare scalar not a struct.  All are intentionally absent --
 * asserting sizeof(struct) against a zero _IOC_SIZE or a scalar
 * would be the wrong shape of check.
 */
_Static_assert(sizeof(struct hpet_info) ==
	       _IOC_SIZE(HPET_INFO),
	       "hpet_info size vs _IOC_SIZE mismatch");

static const struct ioctl hpet_ioctls[] = {
	IOCTL(HPET_IE_ON),
	IOCTL(HPET_IE_OFF),
	IOCTL(HPET_INFO),
	IOCTL(HPET_EPI),
	IOCTL(HPET_DPI),
	IOCTL(HPET_IRQFREQ),
};

static const char *const hpet_devs[] = {
	"hpet",
};

static const struct ioctl_group hpet_grp = {
	.devtype = DEV_MISC,
	.devs = hpet_devs,
	.devs_cnt = ARRAY_SIZE(hpet_devs),
	.sanitise = pick_random_ioctl,
	.ioctls = hpet_ioctls,
	.ioctls_cnt = ARRAY_SIZE(hpet_ioctls),
};

REG_IOCTL_GROUP(hpet_grp)
