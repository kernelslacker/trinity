#include <sys/ioctl.h>
#include <linux/kd.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"
#include "vt-internal.h"

/* Unimap family */

static void sanitise_vt_unimapdesc(struct syscallrecord *rec)
{
	struct unimapdesc *d;
	unsigned short cnt;
	struct unipair *pairs;
	unsigned short i;

	d = get_writable_struct(sizeof(*d));
	if (!d)
		return;
	memset(d, 0, sizeof(*d));
	cnt = rnd_modulo_u32(256) + 1;
	pairs = get_writable_struct(cnt * sizeof(*pairs));
	if (pairs) {
		for (i = 0; i < cnt; i++) {
			pairs[i].unicode = rnd_u32() & 0xffff;
			pairs[i].fontpos = rnd_modulo_u32(512);
		}
		d->entry_ct = cnt;
		d->entries  = pairs;
	} else {
		d->entry_ct = 0;
		d->entries  = NULL;
	}
	rec->a3 = (unsigned long) d;
}

static void sanitise_vt_unimapinit(struct syscallrecord *rec)
{
	struct unimapinit *u;

	u = get_writable_struct(sizeof(*u));
	if (!u)
		return;
	memset(u, 0, sizeof(*u));
	/* 0 = kernel chooses; otherwise a power-of-two hint */
	u->advised_hashsize  = RAND_BOOL() ? 0 : (1 << (rnd_modulo_u32(8) + 4));
	u->advised_hashstep  = RAND_BOOL() ? 0 : (rnd_modulo_u32(16) + 1);
	u->advised_hashlevel = RAND_BOOL() ? 0 : (rnd_modulo_u32(8) + 1);
	rec->a3 = (unsigned long) u;
}

/* Unimap family */
void vt_sanitise_unimap(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case GIO_UNIMAP:
	case PIO_UNIMAP:
		sanitise_vt_unimapdesc(rec);
		break;

	case PIO_UNIMAPCLR:
		sanitise_vt_unimapinit(rec);
		break;

	default:
		break;
	}
}
