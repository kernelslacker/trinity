#include <linux/ioctl.h>
#include <linux/rtc.h>

#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

static void fill_rtc_time(struct rtc_time *t)
{
	t->tm_sec = rand() % 60;
	t->tm_min = rand() % 60;
	t->tm_hour = rand() % 24;
	t->tm_mday = rand() % 31 + 1;
	t->tm_mon = rand() % 12;
	t->tm_year = rand() % 130 + 70;	/* 1970-2099 relative to 1900 */
	t->tm_wday = rand() % 7;
	t->tm_yday = rand() % 366;
	t->tm_isdst = RAND_BOOL();
}

static void sanitise_rtc_time(struct syscallrecord *rec)
{
	struct rtc_time *t;

	t = (struct rtc_time *) get_writable_struct(sizeof(*t));
	if (!t)
		return;
	fill_rtc_time(t);
	rec->a3 = (unsigned long) t;
}

static void sanitise_rtc_wkalrm(struct syscallrecord *rec)
{
	struct rtc_wkalrm *alrm;

	alrm = (struct rtc_wkalrm *) get_writable_struct(sizeof(*alrm));
	if (!alrm)
		return;
	alrm->enabled = RAND_BOOL();
	alrm->pending = RAND_BOOL();
	fill_rtc_time(&alrm->time);
	rec->a3 = (unsigned long) alrm;
}

static void sanitise_rtc_pll_info(struct syscallrecord *rec)
{
	struct rtc_pll_info *pll;

	pll = (struct rtc_pll_info *) get_writable_struct(sizeof(*pll));
	if (!pll)
		return;
	pll->pll_ctrl = rand();
	pll->pll_value = (int)(rand() % 201) - 100;	/* -100 to 100 */
	pll->pll_max = rand() % 1000;
	pll->pll_min = -(int)(rand() % 1000);
	pll->pll_posmult = rand() % 8 + 1;
	pll->pll_negmult = rand() % 8 + 1;
	pll->pll_clock = rand() % 1000000 + 1;
	rec->a3 = (unsigned long) pll;
}

static void rtc_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case RTC_ALM_SET:
	case RTC_ALM_READ:
	case RTC_RD_TIME:
	case RTC_SET_TIME:
		sanitise_rtc_time(rec);
		break;

	case RTC_WKALM_SET:
	case RTC_WKALM_RD:
		sanitise_rtc_wkalrm(rec);
		break;

	case RTC_PLL_GET:
	case RTC_PLL_SET:
		sanitise_rtc_pll_info(rec);
		break;

	case RTC_IRQP_READ:
	case RTC_IRQP_SET:
	case RTC_EPOCH_READ:
	case RTC_EPOCH_SET: {
		unsigned long *p = (unsigned long *) get_writable_struct(sizeof(unsigned long));
		if (p) {
			*p = rand();
			rec->a3 = (unsigned long) p;
		}
		break;
	}

#ifdef RTC_VL_READ
	case RTC_VL_READ: {
		unsigned int *p = (unsigned int *) get_writable_struct(sizeof(unsigned int));
		if (p)
			rec->a3 = (unsigned long) p;
		break;
	}
#endif

	/* _IO ioctls: no pointer argument; leave default from pick_random_ioctl */
	case RTC_AIE_ON:
	case RTC_AIE_OFF:
	case RTC_UIE_ON:
	case RTC_UIE_OFF:
	case RTC_PIE_ON:
	case RTC_PIE_OFF:
	case RTC_WIE_ON:
	case RTC_WIE_OFF:
#ifdef RTC_VL_CLR
	case RTC_VL_CLR:
#endif
		break;

	default:
		break;
	}
}

static const struct ioctl rtc_ioctls[] = {
	IOCTL(RTC_AIE_ON),
	IOCTL(RTC_AIE_OFF),
	IOCTL(RTC_UIE_ON),
	IOCTL(RTC_UIE_OFF),
	IOCTL(RTC_PIE_ON),
	IOCTL(RTC_PIE_OFF),
	IOCTL(RTC_WIE_ON),
	IOCTL(RTC_WIE_OFF),
	IOCTL(RTC_ALM_SET),
	IOCTL(RTC_ALM_READ),
	IOCTL(RTC_RD_TIME),
	IOCTL(RTC_SET_TIME),
	IOCTL(RTC_IRQP_READ),
	IOCTL(RTC_IRQP_SET),
	IOCTL(RTC_EPOCH_READ),
	IOCTL(RTC_EPOCH_SET),
	IOCTL(RTC_WKALM_SET),
	IOCTL(RTC_WKALM_RD),
	IOCTL(RTC_PLL_GET),
	IOCTL(RTC_PLL_SET),
#ifdef RTC_VL_READ
	IOCTL(RTC_VL_READ),
#endif
#ifdef RTC_VL_CLR
	IOCTL(RTC_VL_CLR),
#endif
#ifdef RTC_PARAM_GET
	IOCTL(RTC_PARAM_GET),
#endif
#ifdef RTC_PARAM_SET
	IOCTL(RTC_PARAM_SET),
#endif
};

static const char *const rtc_devs[] = {
	"rtc",
};

static const struct ioctl_group rtc_grp = {
	.devtype = DEV_CHAR,
	.devs = rtc_devs,
	.devs_cnt = ARRAY_SIZE(rtc_devs),
	.sanitise = rtc_sanitise,
	.ioctls = rtc_ioctls,
	.ioctls_cnt = ARRAY_SIZE(rtc_ioctls),
};

REG_IOCTL_GROUP(rtc_grp)
