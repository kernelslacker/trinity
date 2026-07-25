#include <sys/ioctl.h>
#include <linux/kd.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"
#include "vt-internal.h"

/* PIO/GIO font and screenmap family */

static void sanitise_vt_font_raw(struct syscallrecord *rec)
{
	/* GIO_FONT/PIO_FONT: raw 8192-byte buffer, 256 chars × 32 rows */
	void *buf = get_writable_struct(8192);

	if (buf)
		rec->a3 = (unsigned long) buf;
}

static void sanitise_vt_consolefontdesc(struct syscallrecord *rec)
{
	struct consolefontdesc *d;
	unsigned int charcount, charheight;
	void *chardata;

	d = get_writable_struct(sizeof(*d));
	if (!d)
		return;
	memset(d, 0, sizeof(*d));
	charcount  = RAND_BOOL() ? 256 : 512;
	charheight = rnd_modulo_u32(25) + 8;		/* 8-32 scan lines */
	d->charheight = charheight;
	chardata = get_writable_struct(charcount * 32);
	if (chardata) {
		d->chardata  = chardata;
		d->charcount = charcount;
	} else {
		d->chardata  = NULL;
		d->charcount = 0;
	}
	rec->a3 = (unsigned long) d;
}

static void sanitise_vt_scrnmap(struct syscallrecord *rec)
{
	/* GIO_SCRNMAP/PIO_SCRNMAP: char[256] */
	void *buf = get_writable_struct(E_TABSZ);

	if (buf)
		rec->a3 = (unsigned long) buf;
}

static void sanitise_vt_uniscrnmap(struct syscallrecord *rec)
{
	/* GIO_UNISCRNMAP/PIO_UNISCRNMAP: __u32[256] */
	void *buf = get_writable_struct(E_TABSZ * sizeof(__u32));

	if (buf)
		rec->a3 = (unsigned long) buf;
}

static void sanitise_vt_cmap(struct syscallrecord *rec)
{
	/* GIO_CMAP/PIO_CMAP: 16 × 3-byte RGB palette = 48 bytes */
	void *buf = get_writable_struct(16 * 3);

	if (buf)
		rec->a3 = (unsigned long) buf;
}

/* PIO/GIO font and screenmap family */
void vt_sanitise_font(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case GIO_FONT:
	case PIO_FONT:
		sanitise_vt_font_raw(rec);
		break;

	case GIO_FONTX:
	case PIO_FONTX:
		sanitise_vt_consolefontdesc(rec);
		break;

	case GIO_SCRNMAP:
	case PIO_SCRNMAP:
		sanitise_vt_scrnmap(rec);
		break;

	case GIO_UNISCRNMAP:
	case PIO_UNISCRNMAP:
		sanitise_vt_uniscrnmap(rec);
		break;

	case GIO_CMAP:
	case PIO_CMAP:
		sanitise_vt_cmap(rec);
		break;

	default:
		break;
	}
}
