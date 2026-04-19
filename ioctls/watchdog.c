#include <linux/watchdog.h>

#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

/* WDIOC_SETOPTIONS flags */
#define WDIOS_DISABLECARD	0x0001
#define WDIOS_ENABLECARD	0x0002
#define WDIOS_TEMPPANIC		0x0004

static void watchdog_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case WDIOC_GETSUPPORT: {
		/* output only: kernel fills watchdog_info for us */
		struct watchdog_info *info = get_writable_struct(sizeof(*info));
		if (info)
			rec->a3 = (unsigned long) info;
		break;
	}

	case WDIOC_GETSTATUS:
	case WDIOC_GETBOOTSTATUS:
	case WDIOC_GETTEMP:
	case WDIOC_GETTIMEOUT:
	case WDIOC_GETPRETIMEOUT:
	case WDIOC_GETTIMELEFT:
	case WDIOC_KEEPALIVE: {
		/* output (or no-op): provide a writable int buffer */
		int *p = (int *) get_writable_struct(sizeof(int));
		if (p)
			rec->a3 = (unsigned long) p;
		break;
	}

	case WDIOC_SETOPTIONS: {
		/* kernel reads options bitmask from user pointer */
		int *opts = (int *) get_writable_struct(sizeof(int));
		if (opts) {
			static const int option_flags[] = {
				WDIOS_DISABLECARD,
				WDIOS_ENABLECARD,
				WDIOS_TEMPPANIC,
			};
			*opts = option_flags[rand() % ARRAY_SIZE(option_flags)];
			rec->a3 = (unsigned long) opts;
		}
		break;
	}

	case WDIOC_SETTIMEOUT: {
		/* IOWR: user provides timeout in seconds, kernel writes back actual value */
		int *timeout = (int *) get_writable_struct(sizeof(int));
		if (timeout) {
			*timeout = rand() % 300 + 1;
			rec->a3 = (unsigned long) timeout;
		}
		break;
	}

	case WDIOC_SETPRETIMEOUT: {
		/* IOWR: pre-timeout in seconds, must be less than main timeout */
		int *pretimeout = (int *) get_writable_struct(sizeof(int));
		if (pretimeout) {
			*pretimeout = rand() % 60;
			rec->a3 = (unsigned long) pretimeout;
		}
		break;
	}

	default:
		break;
	}
}

static const struct ioctl watchdog_ioctls[] = {
	IOCTL(WDIOC_GETSUPPORT),
	IOCTL(WDIOC_GETSTATUS),
	IOCTL(WDIOC_GETBOOTSTATUS),
	IOCTL(WDIOC_GETTEMP),
	IOCTL(WDIOC_SETOPTIONS),
	IOCTL(WDIOC_KEEPALIVE),
	IOCTL(WDIOC_SETTIMEOUT),
	IOCTL(WDIOC_GETTIMEOUT),
	IOCTL(WDIOC_SETPRETIMEOUT),
	IOCTL(WDIOC_GETPRETIMEOUT),
	IOCTL(WDIOC_GETTIMELEFT),
};

static const char *const watchdog_devs[] = {
	"watchdog",
};

static const struct ioctl_group watchdog_grp_misc = {
	.devtype = DEV_MISC,
	.devs = watchdog_devs,
	.devs_cnt = ARRAY_SIZE(watchdog_devs),
	.sanitise = watchdog_sanitise,
	.ioctls = watchdog_ioctls,
	.ioctls_cnt = ARRAY_SIZE(watchdog_ioctls),
};

REG_IOCTL_GROUP(watchdog_grp_misc)

static const struct ioctl_group watchdog_grp_char = {
	.devtype = DEV_CHAR,
	.devs = watchdog_devs,
	.devs_cnt = ARRAY_SIZE(watchdog_devs),
	.sanitise = watchdog_sanitise,
	.ioctls = watchdog_ioctls,
	.ioctls_cnt = ARRAY_SIZE(watchdog_ioctls),
};

REG_IOCTL_GROUP(watchdog_grp_char)
