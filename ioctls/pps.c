/* /dev/pps[N] PPS (Pulse Per Second) chrdev ioctl fuzzing.
 *
 * uapi reference:
 *   include/uapi/linux/pps.h
 *
 * The pps core (drivers/pps/pps.c) registers its char-major dynamically
 * via alloc_chrdev_region() with the literal name "pps", so /proc/devices
 * shows it under "Character devices:" and the standard DEV_CHAR + devs[]
 * match path applies.  Per-device nodes are /dev/pps0, /dev/pps1, ...
 *
 * PPS is a passive timestamp consumer; the worst SETPARAMS can do is
 * desynchronise a clock discipliner on this host.  No firmware-update
 * surface, no out-of-band kernel state.  Server SKUs without a PPS
 * source (devservers, prod fleet) typically don't load pps_core.ko at
 * all and the device node simply won't be present.
 *
 * Note on the _IO* macros: PPS_GETPARAMS et al. encode the type as a
 * pointer (struct pps_kparams *), so _IOC_SIZE() == sizeof(void *) == 8,
 * not sizeof(struct pps_kparams).  The kernel handler dereferences a real
 * struct's worth of memory, so we must back rec->a3 with an actual
 * sizeof(struct ...) buffer via get_writable_struct(); never trust
 * _IOC_SIZE here.
 *
 * PPS_FETCH timeout semantics (drivers/pps/kapi.c::pps_cdev_pps_fetch):
 *   - timeout.sec == 0 && timeout.nsec == 0 -> non-blocking, return now
 *   - timeout.flags & PPS_TIME_INVALID      -> block indefinitely
 *   - otherwise                             -> wait up to timeout
 * Trinity must never block indefinitely, so we always clear
 * PPS_TIME_INVALID and bias hard toward the non-blocking path.
 */

#include <linux/ioctl.h>
#include <linux/pps.h>
#include <string.h>

#include "ioctls.h"
#include "random.h"
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
	t->sec = (__s64) rand();
	t->nsec = rand() % 1000000000;
	/* Never set PPS_TIME_INVALID here; FETCH timeout uses a separate
	 * sanitiser that must keep that bit clear to avoid blocking. */
	t->flags = 0;
}

static unsigned int random_pps_mode(void)
{
	unsigned int mode = 0;
	unsigned int i, k;

	k = rand() % ARRAY_SIZE(pps_mode_bits);
	for (i = 0; i <= k; i++)
		mode |= pps_mode_bits[rand() % ARRAY_SIZE(pps_mode_bits)];
	return mode;
}

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

	/* Mostly the only api version the kernel accepts; occasionally
	 * a random int to exercise the -EINVAL branch. */
	if ((rand() % 8) == 0)
		p->api_version = (int) rand();
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

	/* Bias hard toward non-blocking (sec=0, nsec=0).  Occasionally a
	 * very short timeout -- single-digit milliseconds at most -- to
	 * exercise the wait path without hanging the fuzzer. */
	if ((rand() % 16) == 0) {
		f->timeout.sec = 0;
		f->timeout.nsec = (rand() % 10) * 1000000;
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

	/* Mostly valid combinations to exercise the bind path; occasionally
	 * fully random ints to hit the -EINVAL validators. */
	if ((rand() % 8) == 0) {
		b->tsformat = (int) rand();
		b->edge = (int) rand();
		b->consumer = (int) rand();
	} else {
		b->tsformat = pps_tsformats[rand() % ARRAY_SIZE(pps_tsformats)];
		b->edge = pps_edge_modes[rand() % ARRAY_SIZE(pps_edge_modes)];
		b->consumer = pps_kc_consumers[rand() % ARRAY_SIZE(pps_kc_consumers)];
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
