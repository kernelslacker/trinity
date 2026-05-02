/* /dev/ptpN PTP hardware clock chrdev ioctl fuzzing */

#include <linux/ioctl.h>
#include <linux/ptp_clock.h>
#include <string.h>

#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

static void fill_clock_time(struct ptp_clock_time *t)
{
	t->sec = (__s64) rand64();
	t->nsec = rand();
	t->reserved = 0;
}

static void sanitise_clock_caps(struct syscallrecord *rec)
{
	struct ptp_clock_caps *c;

	c = (struct ptp_clock_caps *) get_writable_struct(sizeof(*c));
	if (!c)
		return;
	memset(c, 0, sizeof(*c));
	rec->a3 = (unsigned long) c;
}

static void sanitise_extts_request(struct syscallrecord *rec)
{
	struct ptp_extts_request *r;

	r = (struct ptp_extts_request *) get_writable_struct(sizeof(*r));
	if (!r)
		return;
	r->index = rand() % 16;
	r->flags = rand() & PTP_EXTTS_VALID_FLAGS;
	r->rsv[0] = 0;
	r->rsv[1] = 0;
	rec->a3 = (unsigned long) r;
}

static void sanitise_perout_request(struct syscallrecord *rec)
{
	struct ptp_perout_request *r;

	r = (struct ptp_perout_request *) get_writable_struct(sizeof(*r));
	if (!r)
		return;
	memset(r, 0, sizeof(*r));
	fill_clock_time(&r->start);
	fill_clock_time(&r->period);
	r->index = rand() % 16;
	r->flags = rand() & PTP_PEROUT_VALID_FLAGS;
	if (r->flags & PTP_PEROUT_DUTY_CYCLE)
		fill_clock_time(&r->on);
	rec->a3 = (unsigned long) r;
}

static void sanitise_pps_enable(struct syscallrecord *rec)
{
	int *p;

	p = (int *) get_writable_struct(sizeof(int));
	if (!p)
		return;
	*p = RAND_BOOL();
	rec->a3 = (unsigned long) p;
}

static void sanitise_sys_offset(struct syscallrecord *rec)
{
	struct ptp_sys_offset *o;

	o = (struct ptp_sys_offset *) get_writable_struct(sizeof(*o));
	if (!o)
		return;
	memset(o, 0, sizeof(*o));
	o->n_samples = rand() % (PTP_MAX_SAMPLES + 1);
	rec->a3 = (unsigned long) o;
}

static void sanitise_sys_offset_precise(struct syscallrecord *rec)
{
	struct ptp_sys_offset_precise *o;

	o = (struct ptp_sys_offset_precise *) get_writable_struct(sizeof(*o));
	if (!o)
		return;
	memset(o, 0, sizeof(*o));
	rec->a3 = (unsigned long) o;
}

static void sanitise_sys_offset_extended(struct syscallrecord *rec)
{
	struct ptp_sys_offset_extended *o;

	o = (struct ptp_sys_offset_extended *) get_writable_struct(sizeof(*o));
	if (!o)
		return;
	memset(o, 0, sizeof(*o));
	o->n_samples = rand() % (PTP_MAX_SAMPLES + 1);
	rec->a3 = (unsigned long) o;
}

static void sanitise_pin_desc(struct syscallrecord *rec)
{
	struct ptp_pin_desc *p;

	p = (struct ptp_pin_desc *) get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	p->index = rand() % 16;
	p->func = rand() % (PTP_PF_PHYSYNC + 1);
	p->chan = rand() % 16;
	rec->a3 = (unsigned long) p;
}

static void sanitise_mask_en_single(struct syscallrecord *rec)
{
	unsigned int *p;

	p = (unsigned int *) get_writable_struct(sizeof(unsigned int));
	if (!p)
		return;
	*p = rand() % 16;
	rec->a3 = (unsigned long) p;
}

static void ptp_clock_sanitise(const struct ioctl_group *grp,
			       struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case PTP_CLOCK_GETCAPS:
		sanitise_clock_caps(rec);
		break;

	case PTP_EXTTS_REQUEST:
#ifdef PTP_EXTTS_REQUEST2
	case PTP_EXTTS_REQUEST2:
#endif
		sanitise_extts_request(rec);
		break;

	case PTP_PEROUT_REQUEST:
#ifdef PTP_PEROUT_REQUEST2
	case PTP_PEROUT_REQUEST2:
#endif
		sanitise_perout_request(rec);
		break;

	case PTP_ENABLE_PPS:
		sanitise_pps_enable(rec);
		break;

	case PTP_SYS_OFFSET:
		sanitise_sys_offset(rec);
		break;

	case PTP_PIN_GETFUNC:
	case PTP_PIN_SETFUNC:
#ifdef PTP_PIN_GETFUNC2
	case PTP_PIN_GETFUNC2:
#endif
#ifdef PTP_PIN_SETFUNC2
	case PTP_PIN_SETFUNC2:
#endif
		sanitise_pin_desc(rec);
		break;

#ifdef PTP_SYS_OFFSET_PRECISE
	case PTP_SYS_OFFSET_PRECISE:
#endif
#ifdef PTP_SYS_OFFSET_PRECISE2
	case PTP_SYS_OFFSET_PRECISE2:
#endif
#if defined(PTP_SYS_OFFSET_PRECISE) || defined(PTP_SYS_OFFSET_PRECISE2)
		sanitise_sys_offset_precise(rec);
		break;
#endif

#ifdef PTP_SYS_OFFSET_EXTENDED
	case PTP_SYS_OFFSET_EXTENDED:
#endif
#ifdef PTP_SYS_OFFSET_EXTENDED2
	case PTP_SYS_OFFSET_EXTENDED2:
#endif
#if defined(PTP_SYS_OFFSET_EXTENDED) || defined(PTP_SYS_OFFSET_EXTENDED2)
		sanitise_sys_offset_extended(rec);
		break;
#endif

#ifdef PTP_MASK_EN_SINGLE
	case PTP_MASK_EN_SINGLE:
		sanitise_mask_en_single(rec);
		break;
#endif

#ifdef PTP_MASK_CLEAR_ALL
	case PTP_MASK_CLEAR_ALL:
		/* _IO ioctl: no argument. */
		break;
#endif

	default:
		break;
	}
}

static const struct ioctl ptp_clock_ioctls[] = {
	IOCTL(PTP_CLOCK_GETCAPS),
	IOCTL(PTP_EXTTS_REQUEST),
	IOCTL(PTP_PEROUT_REQUEST),
	IOCTL(PTP_ENABLE_PPS),
	IOCTL(PTP_SYS_OFFSET),
	IOCTL(PTP_PIN_GETFUNC),
	IOCTL(PTP_PIN_SETFUNC),
#ifdef PTP_SYS_OFFSET_PRECISE
	IOCTL(PTP_SYS_OFFSET_PRECISE),
#endif
#ifdef PTP_SYS_OFFSET_EXTENDED
	IOCTL(PTP_SYS_OFFSET_EXTENDED),
#endif
#ifdef PTP_EXTTS_REQUEST2
	IOCTL(PTP_EXTTS_REQUEST2),
#endif
#ifdef PTP_PEROUT_REQUEST2
	IOCTL(PTP_PEROUT_REQUEST2),
#endif
#ifdef PTP_PIN_GETFUNC2
	IOCTL(PTP_PIN_GETFUNC2),
#endif
#ifdef PTP_PIN_SETFUNC2
	IOCTL(PTP_PIN_SETFUNC2),
#endif
#ifdef PTP_SYS_OFFSET_PRECISE2
	IOCTL(PTP_SYS_OFFSET_PRECISE2),
#endif
#ifdef PTP_SYS_OFFSET_EXTENDED2
	IOCTL(PTP_SYS_OFFSET_EXTENDED2),
#endif
#ifdef PTP_MASK_CLEAR_ALL
	IOCTL(PTP_MASK_CLEAR_ALL),
#endif
#ifdef PTP_MASK_EN_SINGLE
	IOCTL(PTP_MASK_EN_SINGLE),
#endif
};

/*
 * The PTP subsystem dynamically allocates a char major and registers
 * itself in /proc/devices as "ptp", with per-clock minors backing
 * /dev/ptp0, /dev/ptp1, ...  map_dev() returns the driver name from
 * /proc/devices, so matching on "ptp" catches every PHC device.
 */
static const char *const ptp_clock_devs[] = {
	"ptp",
};

static const struct ioctl_group ptp_clock_grp = {
	.name = "ptp_clock",
	.devtype = DEV_CHAR,
	.devs = ptp_clock_devs,
	.devs_cnt = ARRAY_SIZE(ptp_clock_devs),
	.sanitise = ptp_clock_sanitise,
	.ioctls = ptp_clock_ioctls,
	.ioctls_cnt = ARRAY_SIZE(ptp_clock_ioctls),
};

REG_IOCTL_GROUP(ptp_clock_grp)
