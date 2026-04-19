#include <sys/vt.h>
#include <sys/ioctl.h>
#include <linux/kd.h>
#include <linux/serial.h>
#include <termios.h>

#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

#ifndef HAVE_TERMIOS2
typedef unsigned char   cc_t;
typedef unsigned int    speed_t;
typedef unsigned int    tcflag_t;

#ifndef NCCS
#define NCCS 19
#endif
struct termios2 {
        tcflag_t c_iflag;               /* input mode flags */
        tcflag_t c_oflag;               /* output mode flags */
        tcflag_t c_cflag;               /* control mode flags */
        tcflag_t c_lflag;               /* local mode flags */
        cc_t c_line;                    /* line discipline */
        cc_t c_cc[NCCS];                /* control characters */
        speed_t c_ispeed;               /* input speed */
        speed_t c_ospeed;               /* output speed */
};
#endif

/* KD* family */

static void sanitise_vt_console_font_op(struct syscallrecord *rec)
{
	struct console_font_op *op;
	unsigned int charcount;

	op = get_writable_struct(sizeof(*op));
	if (!op)
		return;
	op->op = rand() % 6;	/* KD_FONT_OP_SET=0 .. KD_FONT_OP_GET_TALL=5 */
	op->flags = RAND_BOOL() ? KD_FONT_FLAG_DONT_RECALC : 0;
	op->width = rand() % 8 + 8;	/* 8-15 pixels wide */
	op->height = rand() % 25 + 8;	/* 8-32 pixels tall */
	charcount = RAND_BOOL() ? 256 : 512;
	op->charcount = charcount;
	op->data = get_writable_struct(charcount * 32);
	rec->a3 = (unsigned long) op;
}

static void sanitise_vt_kbentry(struct syscallrecord *rec)
{
	struct kbentry *e;

	e = get_writable_struct(sizeof(*e));
	if (!e)
		return;
	e->kb_table = rand() & 0x0f;	/* 0-15: modifier-table index */
	e->kb_index = rand() & 0x7f;	/* 0-127: key index */
	e->kb_value = rand() & 0xffff;
	rec->a3 = (unsigned long) e;
}

static void sanitise_vt_kbsentry(struct syscallrecord *rec)
{
	struct kbsentry *s;
	unsigned int len;

	s = get_writable_struct(sizeof(*s));
	if (!s)
		return;
	s->kb_func = rand() & 0xff;
	len = rand() % (sizeof(s->kb_string) - 1);
	if (len) {
		unsigned int i;

		for (i = 0; i < len; i++)
			s->kb_string[i] = (rand() % 94) + 33;	/* printable ASCII */
		s->kb_string[len] = '\0';
	} else {
		s->kb_string[0] = '\0';
	}
	rec->a3 = (unsigned long) s;
}

static void sanitise_vt_kbdiacrs(struct syscallrecord *rec)
{
	struct kbdiacrs *d;
	unsigned int i, cnt;

	d = get_writable_struct(sizeof(*d));
	if (!d)
		return;
	cnt = rand() % 256;
	d->kb_cnt = cnt;
	for (i = 0; i < cnt; i++) {
		d->kbdiacr[i].diacr  = rand() & 0xff;
		d->kbdiacr[i].base   = rand() & 0xff;
		d->kbdiacr[i].result = rand() & 0xff;
	}
	rec->a3 = (unsigned long) d;
}

static void sanitise_vt_kbdiacrsuc(struct syscallrecord *rec)
{
	struct kbdiacrsuc *d;
	unsigned int i, cnt;

	d = get_writable_struct(sizeof(*d));
	if (!d)
		return;
	cnt = rand() % 256;
	d->kb_cnt = cnt;
	for (i = 0; i < cnt; i++) {
		d->kbdiacruc[i].diacr  = rand();
		d->kbdiacruc[i].base   = rand();
		d->kbdiacruc[i].result = rand();
	}
	rec->a3 = (unsigned long) d;
}

static void sanitise_vt_kbkeycode(struct syscallrecord *rec)
{
	struct kbkeycode *k;

	k = get_writable_struct(sizeof(*k));
	if (!k)
		return;
	k->scancode = rand();
	k->keycode  = rand() % 256;
	rec->a3 = (unsigned long) k;
}

static void sanitise_vt_kbd_repeat(struct syscallrecord *rec)
{
	struct kbd_repeat *r;

	r = get_writable_struct(sizeof(*r));
	if (!r)
		return;
	r->delay  = rand() % 1000 + 1;	/* 1-1000 ms */
	r->period = rand() % 500  + 1;	/* 1-500 ms */
	rec->a3 = (unsigned long) r;
}

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
	cnt = rand() % 256 + 1;
	pairs = get_writable_struct(cnt * sizeof(*pairs));
	if (pairs) {
		for (i = 0; i < cnt; i++) {
			pairs[i].unicode = rand() & 0xffff;
			pairs[i].fontpos = rand() % 512;
		}
	}
	d->entry_ct = cnt;
	d->entries  = pairs;
	rec->a3 = (unsigned long) d;
}

static void sanitise_vt_unimapinit(struct syscallrecord *rec)
{
	struct unimapinit *u;

	u = get_writable_struct(sizeof(*u));
	if (!u)
		return;
	/* 0 = kernel chooses; otherwise a power-of-two hint */
	u->advised_hashsize  = RAND_BOOL() ? 0 : (1 << (rand() % 8 + 4));
	u->advised_hashstep  = RAND_BOOL() ? 0 : (rand() % 16 + 1);
	u->advised_hashlevel = RAND_BOOL() ? 0 : (rand() % 8 + 1);
	rec->a3 = (unsigned long) u;
}

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

	d = get_writable_struct(sizeof(*d));
	if (!d)
		return;
	charcount  = RAND_BOOL() ? 256 : 512;
	charheight = rand() % 25 + 8;		/* 8-32 scan lines */
	d->charcount  = charcount;
	d->charheight = charheight;
	d->chardata   = get_writable_struct(charcount * 32);
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
	m->relsig = rand() % 31 + 1;	/* SIGHUP=1 .. SIGSYS=31 */
	m->acqsig = rand() % 31 + 1;
	m->frsig  = 0;			/* unused, must be 0 */
}

static void sanitise_vt_vt_mode(struct syscallrecord *rec)
{
	struct vt_mode *m;

	m = get_writable_struct(sizeof(*m));
	if (!m)
		return;
	fill_vt_mode(m);
	rec->a3 = (unsigned long) m;
}

static void sanitise_vt_vt_stat(struct syscallrecord *rec)
{
	struct vt_stat *s;

	s = get_writable_struct(sizeof(*s));
	if (!s)
		return;
	s->v_active = rand() % 63 + 1;		/* VT 1-63 */
	s->v_signal = rand() % 31 + 1;
	s->v_state  = rand() & 0xffff;
	rec->a3 = (unsigned long) s;
}

static void sanitise_vt_vt_sizes(struct syscallrecord *rec)
{
	struct vt_sizes *sz;

	sz = get_writable_struct(sizeof(*sz));
	if (!sz)
		return;
	sz->v_rows       = rand() % 50 + 24;	/* 24-73 rows */
	sz->v_cols       = rand() % 120 + 80;	/* 80-199 columns */
	sz->v_scrollsize = rand() % 256;
	rec->a3 = (unsigned long) sz;
}

static void sanitise_vt_vt_consize(struct syscallrecord *rec)
{
	struct vt_consize *c;
	unsigned int rows, cols;

	c = get_writable_struct(sizeof(*c));
	if (!c)
		return;
	rows = rand() % 50 + 24;
	cols = rand() % 120 + 80;
	c->v_rows = rows;
	c->v_cols = cols;
	c->v_vlin = rows * (rand() % 16 + 8);	/* rows * cell_height pixels */
	c->v_clin = rand() % 16 + 8;
	c->v_vcol = cols * (rand() % 8 + 8);	/* cols * cell_width pixels */
	c->v_ccol = rand() % 8 + 8;
	rec->a3 = (unsigned long) c;
}

static void sanitise_vt_vt_event(struct syscallrecord *rec)
{
	struct vt_event *e;

	e = get_writable_struct(sizeof(*e));
	if (!e)
		return;
	e->event = rand() & VT_MAX_EVENT;
	e->oldev = rand() % 63 + 1;
	e->newev = rand() % 63 + 1;
	rec->a3 = (unsigned long) e;
}

static void sanitise_vt_setactivate(struct syscallrecord *rec)
{
	struct vt_setactivate *sa;

	sa = get_writable_struct(sizeof(*sa));
	if (!sa)
		return;
	sa->console = rand() % 63 + 1;
	fill_vt_mode(&sa->mode);
	rec->a3 = (unsigned long) sa;
}

static void vt_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case KDFONTOP:
		sanitise_vt_console_font_op(rec);
		break;

	case KDGKBENT:
	case KDSKBENT:
		sanitise_vt_kbentry(rec);
		break;

	case KDGKBSENT:
	case KDSKBSENT:
		sanitise_vt_kbsentry(rec);
		break;

	case KDGKBDIACR:
	case KDSKBDIACR:
		sanitise_vt_kbdiacrs(rec);
		break;

	case KDGKBDIACRUC:
	case KDSKBDIACRUC:
		sanitise_vt_kbdiacrsuc(rec);
		break;

	case KDGETKEYCODE:
	case KDSETKEYCODE:
		sanitise_vt_kbkeycode(rec);
		break;

	case KDKBDREP:
		sanitise_vt_kbd_repeat(rec);
		break;

	/* scalar arg: LED bitmask */
	case KDSETLED:
		rec->a3 = rand() & (LED_SCR | LED_NUM | LED_CAP);
		break;

	/* scalar arg: mode */
	case KDSETMODE:
		rec->a3 = rand() % 4;	/* KD_TEXT=0 .. KD_TEXT1=3 */
		break;

	/* scalar arg: keyboard mode */
	case KDSKBMODE:
		rec->a3 = rand() % 5;	/* K_RAW=0 .. K_OFF=4 */
		break;

	/* scalar arg: meta handling mode */
	case KDSKBMETA:
		rec->a3 = RAND_BOOL() ? K_METABIT : K_ESCPREFIX;
		break;

	/* scalar arg: led flags */
	case KDSKBLED:
		rec->a3 = rand() & (K_SCROLLLOCK | K_NUMLOCK | K_CAPSLOCK);
		break;

	/* scalar arg: I/O port number */
	case KDADDIO:
	case KDDELIO:
		rec->a3 = rand() % 0x3ff + 1;	/* low I/O port range */
		break;

	/* scalar arg: sound frequency (Hz) or 0 for off */
	case KIOCSOUND:
		rec->a3 = RAND_BOOL() ? 0 : (rand() % 4000 + 200);
		break;

	/* scalar arg: frequency and duration packed */
	case KDMKTONE:
		rec->a3 = ((rand() % 4000 + 200) & 0xffff) |
			  ((rand() % 2000) << 16);
		break;

	/* scalar arg: signal number */
	case KDSIGACCEPT:
		rec->a3 = rand() % 32 + 1;
		break;

	/* VT_* family */
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
		rec->a3 = rand() % 63 + 1;	/* VT number 1-63 */
		break;

	case VT_RELDISP:
		/* 0 = refuse, 1 = release, VT_ACKACQ = acknowledge acquire */
		rec->a3 = rand() % 3;
		break;

	case VT_GETHIFONTMASK: {
		unsigned short *p = get_writable_struct(sizeof(unsigned short));

		if (p)
			rec->a3 = (unsigned long) p;
		break;
	}

	/* PIO/GIO font and screenmap family */
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

	/* Unimap family */
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
