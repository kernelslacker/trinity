/* /dev/pps[N] PPS (Pulse Per Second) chrdev ioctl fuzzing; uapi: linux/pps.h.
 *
 * PPS is a passive timestamp consumer: the worst SETPARAMS can do is
 * desynchronise a clock discipliner on this host, and there is no
 * firmware-update surface or out-of-band kernel state.
 */

#include <linux/ioctl.h>
#include <linux/pps.h>
#include <string.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

static const unsigned int pps_mode_bits[] = {
	PPS_CAPTUREASSERT,
	PPS_CAPTURECLEAR,
	PPS_OFFSETASSERT,
	PPS_OFFSETCLEAR,
	PPS_ECHOASSERT,
	PPS_ECHOCLEAR,
	PPS_TSFMT_TSPEC,
	PPS_TSFMT_NTPFP,
};

static const int pps_kc_consumers[] = {
	PPS_KC_HARDPPS,
	PPS_KC_HARDPPS_PLL,
	PPS_KC_HARDPPS_FLL,
};

static const int pps_edge_modes[] = {
	PPS_CAPTUREASSERT,
	PPS_CAPTURECLEAR,
	PPS_CAPTUREBOTH,
};

static const int pps_tsformats[] = {
	PPS_TSFMT_TSPEC,
	PPS_TSFMT_NTPFP,
};

static void fill_pps_ktime(struct pps_ktime *t)
{
	t->sec = (__s64) rnd_u32();
	t->nsec = rnd_modulo_u32(1000000000);
	/* Never set PPS_TIME_INVALID here; FETCH timeout uses a separate
	 * sanitiser that must keep that bit clear to avoid blocking. */
	t->flags = 0;
}

static unsigned int random_pps_mode(void)
{
	unsigned int mode = 0;
	unsigned int i, k;

	k = rnd_modulo_u32(ARRAY_SIZE(pps_mode_bits));
	for (i = 0; i <= k; i++)
		mode |= pps_mode_bits[rnd_modulo_u32(ARRAY_SIZE(pps_mode_bits))];
	return mode;
}

/*
 * The request numbers encode the arg as a pointer (struct pps_kparams *),
 * so _IOC_SIZE() is sizeof(void *), not the struct's size.  The handlers
 * read a full struct, so every sanitiser here backs a3 with a real
 * sizeof(struct ...) buffer from get_writable_struct() and never trusts
 * _IOC_SIZE().
 */
static void sanitise_getparams(struct syscallrecord *rec)
{
	struct pps_kparams *p;

	p = (struct pps_kparams *) get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	rec->a3 = (unsigned long) p;
}

static void sanitise_setparams(struct syscallrecord *rec)
{
	struct pps_kparams *p;

	p = (struct pps_kparams *) get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));

	/* Mostly the only api version the kernel accepts; occasionally
	 * a random int to exercise the -EINVAL branch. */
	if ((rnd_modulo_u32(8)) == 0)
		p->api_version = (int) rnd_u32();
	else
		p->api_version = PPS_API_VERS_1;

	p->mode = (int) random_pps_mode();
	fill_pps_ktime(&p->assert_off_tu);
	fill_pps_ktime(&p->clear_off_tu);

	rec->a3 = (unsigned long) p;
}

static void sanitise_getcap(struct syscallrecord *rec)
{
	int *cap;

	cap = (int *) get_writable_struct(sizeof(*cap));
	if (!cap)
		return;
	memset(cap, 0, sizeof(*cap));
	*cap = 0;
	rec->a3 = (unsigned long) cap;
}

static void sanitise_fetch(struct syscallrecord *rec)
{
	struct pps_fdata *f;

	f = (struct pps_fdata *) get_writable_struct(sizeof(*f));
	if (!f)
		return;
	memset(f, 0, sizeof(*f));

	/* pps_cdev_pps_fetch() in drivers/pps/pps.c: a zero timeout returns
	 * at once, PPS_TIME_INVALID blocks indefinitely, anything else waits
	 * up to the timeout.  Trinity must never block indefinitely, so bias
	 * hard toward non-blocking (sec=0, nsec=0).  Occasionally a very
	 * short timeout -- single-digit milliseconds at most -- to exercise
	 * the wait path without hanging the fuzzer. */
	if ((rnd_modulo_u32(16)) == 0) {
		f->timeout.sec = 0;
		f->timeout.nsec = (rnd_modulo_u32(10)) * 1000000;
	} else {
		f->timeout.sec = 0;
		f->timeout.nsec = 0;
	}
	/* Must stay clear -- PPS_TIME_INVALID means block indefinitely. */
	f->timeout.flags = 0;

	rec->a3 = (unsigned long) f;
}

static void sanitise_kc_bind(struct syscallrecord *rec)
{
	struct pps_bind_args *b;

	b = (struct pps_bind_args *) get_writable_struct(sizeof(*b));
	if (!b)
		return;
	memset(b, 0, sizeof(*b));

	/* Mostly valid combinations to exercise the bind path; occasionally
	 * fully random ints to hit the -EINVAL validators. */
	if ((rnd_modulo_u32(8)) == 0) {
		b->tsformat = (int) rnd_u32();
		b->edge = (int) rnd_u32();
		b->consumer = (int) rnd_u32();
	} else {
		b->tsformat = pps_tsformats[rnd_modulo_u32(ARRAY_SIZE(pps_tsformats))];
		b->edge = pps_edge_modes[rnd_modulo_u32(ARRAY_SIZE(pps_edge_modes))];
		b->consumer = pps_kc_consumers[rnd_modulo_u32(ARRAY_SIZE(pps_kc_consumers))];
	}

	rec->a3 = (unsigned long) b;
}

static void pps_sanitise(const struct ioctl_group *grp,
			 struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case PPS_GETPARAMS:
		sanitise_getparams(rec);
		break;
	case PPS_SETPARAMS:
		sanitise_setparams(rec);
		break;
	case PPS_GETCAP:
		sanitise_getcap(rec);
		break;
	case PPS_FETCH:
		sanitise_fetch(rec);
		break;
	case PPS_KC_BIND:
		sanitise_kc_bind(rec);
		break;
	default:
		break;
	}
}

static const struct ioctl pps_ioctls[] = {
	IOCTL(PPS_GETPARAMS),
	IOCTL(PPS_SETPARAMS),
	IOCTL(PPS_GETCAP),
	IOCTL(PPS_FETCH),
	IOCTL(PPS_KC_BIND),
};

/* The pps core registers a dynamic char major under this literal name
 * (drivers/pps/pps.c), so /proc/devices lists it; nodes are /dev/pps0, ... */
static const char *const pps_devs[] = {
	"pps",
};

static const struct ioctl_group pps_grp = {
	.name = "pps",
	.devtype = DEV_CHAR,
	.devs = pps_devs,
	.devs_cnt = ARRAY_SIZE(pps_devs),
	.sanitise = pps_sanitise,
	.ioctls = pps_ioctls,
	.ioctls_cnt = ARRAY_SIZE(pps_ioctls),
};

REG_IOCTL_GROUP(pps_grp)
