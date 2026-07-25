#include <sys/vt.h>
#include <sys/ioctl.h>
#include <linux/kd.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"
#include "vt-internal.h"

/*
 * Compile-time: VT_GETCONSIZECSRPOS -- the sole _IOR-encoded struct
 * command in the VT_* set -- must match struct vt_consizecsrpos.
 * The bare-numeric KD/VT ioctls dispatched elsewhere in this file
 * (VT_GETMODE, KDGKBENT, ...) carry no size in their request bits
 * (_IOC_SIZE(x) == 0) and are intentionally absent -- a static assert
 * against them would compare sizeof(struct) to 0.
 */
#ifdef VT_GETCONSIZECSRPOS
IOCTL_SIZE_ASSERT(VT_GETCONSIZECSRPOS, struct vt_consizecsrpos);
#endif

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

/* VT_* family */

static void fill_vt_mode(struct vt_mode *m)
{
	m->mode   = RAND_BOOL() ? VT_AUTO : VT_PROCESS;
	m->waitv  = RAND_BOOL();
	m->relsig = rnd_modulo_u32(31) + 1;	/* SIGHUP=1 .. SIGSYS=31 */
	m->acqsig = rnd_modulo_u32(31) + 1;
	m->frsig  = 0;			/* unused, must be 0 */
}

static void sanitise_vt_vt_mode(struct syscallrecord *rec)
{
	struct vt_mode *m;

	m = get_writable_struct(sizeof(*m));
	if (!m)
		return;
	memset(m, 0, sizeof(*m));
	fill_vt_mode(m);
	rec->a3 = (unsigned long) m;
}

static void sanitise_vt_vt_stat(struct syscallrecord *rec)
{
	struct vt_stat *s;

	s = get_writable_struct(sizeof(*s));
	if (!s)
		return;
	memset(s, 0, sizeof(*s));
	s->v_active = rnd_modulo_u32(63) + 1;		/* VT 1-63 */
	s->v_signal = rnd_modulo_u32(31) + 1;
	s->v_state  = rnd_u32() & 0xffff;
	rec->a3 = (unsigned long) s;
}

static void sanitise_vt_vt_sizes(struct syscallrecord *rec)
{
	struct vt_sizes *sz;

	sz = get_writable_struct(sizeof(*sz));
	if (!sz)
		return;
	memset(sz, 0, sizeof(*sz));
	sz->v_rows       = rnd_modulo_u32(50) + 24;	/* 24-73 rows */
	sz->v_cols       = rnd_modulo_u32(120) + 80;	/* 80-199 columns */
	sz->v_scrollsize = rnd_modulo_u32(256);
	rec->a3 = (unsigned long) sz;
}

static void sanitise_vt_vt_consize(struct syscallrecord *rec)
{
	struct vt_consize *c;
	unsigned int rows, cols;

	c = get_writable_struct(sizeof(*c));
	if (!c)
		return;
	memset(c, 0, sizeof(*c));
	rows = rnd_modulo_u32(50) + 24;
	cols = rnd_modulo_u32(120) + 80;
	c->v_rows = rows;
	c->v_cols = cols;
	c->v_vlin = rows * (rnd_modulo_u32(16) + 8);	/* rows * cell_height pixels */
	c->v_clin = rnd_modulo_u32(16) + 8;
	c->v_vcol = cols * (rnd_modulo_u32(8) + 8);	/* cols * cell_width pixels */
	c->v_ccol = rnd_modulo_u32(8) + 8;
	rec->a3 = (unsigned long) c;
}

static void sanitise_vt_vt_event(struct syscallrecord *rec)
{
	struct vt_event *e;

	e = get_writable_struct(sizeof(*e));
	if (!e)
		return;
	memset(e, 0, sizeof(*e));
	e->event = rnd_u32() & VT_MAX_EVENT;
	e->oldev = rnd_modulo_u32(63) + 1;
	e->newev = rnd_modulo_u32(63) + 1;
	rec->a3 = (unsigned long) e;
}

static void sanitise_vt_setactivate(struct syscallrecord *rec)
{
	struct vt_setactivate *sa;

	sa = get_writable_struct(sizeof(*sa));
	if (!sa)
		return;
	memset(sa, 0, sizeof(*sa));
	sa->console = rnd_modulo_u32(63) + 1;
	fill_vt_mode(&sa->mode);
	rec->a3 = (unsigned long) sa;
}

/* VT_* family */
static void vt_sanitise_vt(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case VT_GETMODE:
	case VT_SETMODE:
		sanitise_vt_vt_mode(rec);
		break;

	case VT_GETSTATE:
		sanitise_vt_vt_stat(rec);
		break;

	case VT_RESIZE:
		sanitise_vt_vt_sizes(rec);
		break;

	case VT_RESIZEX:
		sanitise_vt_vt_consize(rec);
		break;

	case VT_WAITEVENT:
		sanitise_vt_vt_event(rec);
		break;

	case VT_SETACTIVATE:
		sanitise_vt_setactivate(rec);
		break;

	case VT_ACTIVATE:
	case VT_WAITACTIVE:
	case VT_DISALLOCATE:
		rec->a3 = rnd_modulo_u32(63) + 1;	/* VT number 1-63 */
		break;

	case VT_RELDISP:
		/* 0 = refuse, 1 = release, VT_ACKACQ = acknowledge acquire */
		rec->a3 = rnd_modulo_u32(3);
		break;

	case VT_GETHIFONTMASK: {
		unsigned short *p = get_writable_struct(sizeof(unsigned short));

		if (p)
			rec->a3 = (unsigned long) p;
		break;
	}

#ifdef VT_GETCONSIZECSRPOS
	case VT_GETCONSIZECSRPOS: {
		/* Kernel writes struct vt_consizecsrpos: 4 × __u16. */
		void *p = get_writable_struct(4 * sizeof(unsigned short));

		if (p)
			rec->a3 = (unsigned long) p;
		break;
	}
#endif

	default:
		break;
	}
}

/* PIO/GIO font and screenmap family */
static void vt_sanitise_font(struct syscallrecord *rec)
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

static void vt_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	vt_sanitise_kd(rec);
	vt_sanitise_vt(rec);
	vt_sanitise_font(rec);
	vt_sanitise_unimap(rec);
	vt_sanitise_tioc(rec);
}

static const struct ioctl vt_ioctls[] = {
	IOCTL(VT_OPENQRY),
	IOCTL(VT_GETMODE),
	IOCTL(VT_SETMODE),
	IOCTL(VT_GETSTATE),
	IOCTL(VT_SENDSIG),
	IOCTL(VT_RELDISP),
	IOCTL(VT_ACTIVATE),
	IOCTL(VT_WAITACTIVE),
	IOCTL(VT_DISALLOCATE),
	IOCTL(VT_RESIZE),
	IOCTL(VT_RESIZEX),
	IOCTL(VT_LOCKSWITCH),
	IOCTL(VT_UNLOCKSWITCH),
	IOCTL(VT_GETHIFONTMASK),
	IOCTL(VT_WAITEVENT),
	IOCTL(VT_SETACTIVATE),
#ifdef VT_GETCONSIZECSRPOS
	IOCTL(VT_GETCONSIZECSRPOS),
#endif

	IOCTL(GIO_FONT),
	IOCTL(PIO_FONT),
	IOCTL(GIO_FONTX),
	IOCTL(PIO_FONTX),
	IOCTL(PIO_FONTRESET),
	IOCTL(GIO_CMAP),
	IOCTL(PIO_CMAP),
	IOCTL(KIOCSOUND),
	IOCTL(KDMKTONE),
	IOCTL(KDGETLED),
	IOCTL(KDSETLED),
	IOCTL(KDGKBTYPE),
	IOCTL(KDADDIO),
	IOCTL(KDDELIO),
	IOCTL(KDENABIO),
	IOCTL(KDDISABIO),
	IOCTL(KDSETMODE),
	IOCTL(KDGETMODE),
	IOCTL(KDMAPDISP),
	IOCTL(KDUNMAPDISP),
	IOCTL(GIO_SCRNMAP),
	IOCTL(PIO_SCRNMAP),
	IOCTL(GIO_UNISCRNMAP),
	IOCTL(PIO_UNISCRNMAP),
	IOCTL(GIO_UNIMAP),
	IOCTL(PIO_UNIMAP),
	IOCTL(PIO_UNIMAPCLR),
	IOCTL(KDGKBMODE),
	IOCTL(KDSKBMODE),
	IOCTL(KDGKBMETA),
	IOCTL(KDSKBMETA),
	IOCTL(KDGKBLED),
	IOCTL(KDSKBLED),
	IOCTL(KDGKBENT),
	IOCTL(KDSKBENT),
	IOCTL(KDGKBSENT),
	IOCTL(KDSKBSENT),
	IOCTL(KDGKBDIACR),
	IOCTL(KDSKBDIACR),
	IOCTL(KDGKBDIACRUC),
	IOCTL(KDSKBDIACRUC),
	IOCTL(KDGETKEYCODE),
	IOCTL(KDSETKEYCODE),
	IOCTL(KDSIGACCEPT),
#ifdef KDGKBMUTE
	IOCTL(KDGKBMUTE),
#endif
#ifdef KDSKBMUTE
	IOCTL(KDSKBMUTE),
#endif
	IOCTL(KDKBDREP),
	IOCTL(KDFONTOP),

	IOCTL(TCGETS),
	IOCTL(TCSETS),
	IOCTL(TCSETSW),
	IOCTL(TCSETSF),
	IOCTL(TCGETA),
	IOCTL(TCSETA),
	IOCTL(TCSETAW),
	IOCTL(TCSETAF),
	IOCTL(TCSBRK),
	IOCTL(TCXONC),
	IOCTL(TCFLSH),
	IOCTL(TIOCEXCL),
	IOCTL(TIOCNXCL),
	IOCTL(TIOCSCTTY),
	IOCTL(TIOCGPGRP),
	IOCTL(TIOCSPGRP),
	IOCTL(TIOCOUTQ),
	IOCTL(TIOCSTI),
	IOCTL(TIOCGWINSZ),
	IOCTL(TIOCSWINSZ),
	IOCTL(TIOCMGET),
	IOCTL(TIOCMBIS),
	IOCTL(TIOCMBIC),
	IOCTL(TIOCMSET),
	IOCTL(TIOCGSOFTCAR),
	IOCTL(TIOCSSOFTCAR),
	IOCTL(FIONREAD),
	IOCTL(TIOCLINUX),
	IOCTL(TIOCCONS),
	IOCTL(TIOCGSERIAL),
	IOCTL(TIOCSSERIAL),
	IOCTL(TIOCPKT),
	IOCTL(FIONBIO),
	IOCTL(TIOCNOTTY),
	IOCTL(TIOCSETD),
	IOCTL(TIOCGETD),
	IOCTL(TCSBRKP),
	IOCTL(TIOCSBRK),
	IOCTL(TIOCCBRK),
	IOCTL(TIOCGSID),
#ifdef TCGETS2
	IOCTL(TCGETS2),
#endif
#ifdef TCSETS2
	IOCTL(TCSETS2),
#endif
#ifdef TCSETSW2
	IOCTL(TCSETSW2),
#endif
#ifdef TCSETSF2
	IOCTL(TCSETSF2),
#endif
#ifdef TIOCGRS485
	IOCTL(TIOCGRS485),
#endif
#ifdef TIOCSRS485
	IOCTL(TIOCSRS485),
#endif
	IOCTL(TIOCGPTN),
	IOCTL(TIOCSPTLCK),
#ifdef TIOCGDEV
	IOCTL(TIOCGDEV),
#endif
#ifdef TCGETX
	IOCTL(TCGETX),
#endif
#ifdef TCSETX
	IOCTL(TCSETX),
#endif
#ifdef TCSETXF
	IOCTL(TCSETXF),
#endif
#ifdef TCSETXW
	IOCTL(TCSETXW),
#endif
#ifdef TIOCSIG
	IOCTL(TIOCSIG),
#endif
#ifdef TIOCVHANGUP
	IOCTL(TIOCVHANGUP),
#endif
#ifdef TIOCGPKT
	IOCTL(TIOCGPKT),
#endif
#ifdef TIOCGPTLCK
	IOCTL(TIOCGPTLCK),
#endif
#ifdef TIOCGEXCL
	IOCTL(TIOCGEXCL),
#endif

	IOCTL(FIONCLEX),
	IOCTL(FIOCLEX),
	IOCTL(FIOASYNC),
	IOCTL(TIOCSERCONFIG),
	IOCTL(TIOCSERGWILD),
	IOCTL(TIOCSERSWILD),
	IOCTL(TIOCGLCKTRMIOS),
	IOCTL(TIOCSLCKTRMIOS),
	IOCTL(TIOCSERGSTRUCT),
	IOCTL(TIOCSERGETLSR),
	IOCTL(TIOCSERGETMULTI),
	IOCTL(TIOCSERSETMULTI),
	IOCTL(TIOCMIWAIT),
	IOCTL(TIOCGICOUNT),
	IOCTL(FIOQSIZE),
};

static const char *const vt_devs[] = {
	"tty",
	"ttyS",
	"ptmx",
	"vcs",
};

static const struct ioctl_group vt_grp = {
	.devtype = DEV_CHAR,
	.devs = vt_devs,
	.devs_cnt = ARRAY_SIZE(vt_devs),
	.sanitise = vt_sanitise,
	.ioctls = vt_ioctls,
	.ioctls_cnt = ARRAY_SIZE(vt_ioctls),
};

REG_IOCTL_GROUP(vt_grp)
