#include <sys/ioctl.h>
#include <linux/kd.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"
#include "vt-internal.h"

/* KD* family */

static const unsigned int kd_font_op_vals[] = {
	KD_FONT_OP_SET,
	KD_FONT_OP_GET,
	KD_FONT_OP_SET_DEFAULT,
	KD_FONT_OP_COPY,
	KD_FONT_OP_SET_TALL,
	KD_FONT_OP_GET_TALL,
};

static const unsigned char kd_mode_vals[] = {
	KD_TEXT,
	KD_GRAPHICS,
	KD_TEXT0,
	KD_TEXT1,
};

static const unsigned char kd_kbmode_vals[] = {
	K_RAW,
	K_XLATE,
	K_MEDIUMRAW,
	K_UNICODE,
	K_OFF,
};

static void sanitise_vt_console_font_op(struct syscallrecord *rec)
{
	struct console_font_op *op;
	unsigned int charcount;
	void *data;

	op = get_writable_struct(sizeof(*op));
	if (!op)
		return;
	memset(op, 0, sizeof(*op));
	op->op = RAND_ARRAY(kd_font_op_vals);
	op->flags = RAND_BOOL() ? KD_FONT_FLAG_DONT_RECALC : 0;
	op->width = rnd_modulo_u32(8) + 8;	/* 8-15 pixels wide */
	op->height = rnd_modulo_u32(25) + 8;	/* 8-32 pixels tall */
	charcount = RAND_BOOL() ? 256 : 512;
	data = get_writable_struct(charcount * 32);
	if (data) {
		op->data = data;
		op->charcount = charcount;
	} else {
		op->data = NULL;
		op->charcount = 0;
	}
	rec->a3 = (unsigned long) op;
}

static void sanitise_vt_kbentry(struct syscallrecord *rec)
{
	struct kbentry *e;

	e = get_writable_struct(sizeof(*e));
	if (!e)
		return;
	memset(e, 0, sizeof(*e));
	e->kb_table = rnd_u32() & 0x0f;	/* 0-15: modifier-table index */
	e->kb_index = rnd_u32() & 0x7f;	/* 0-127: key index */
	e->kb_value = rnd_u32() & 0xffff;
	rec->a3 = (unsigned long) e;
}

static void sanitise_vt_kbsentry(struct syscallrecord *rec)
{
	struct kbsentry *s;
	unsigned int len;

	s = get_writable_struct(sizeof(*s));
	if (!s)
		return;
	memset(s, 0, sizeof(*s));
	s->kb_func = rnd_u32() & 0xff;
	len = rnd_modulo_u32((sizeof(s->kb_string) - 1));
	if (len) {
		unsigned int i;

		for (i = 0; i < len; i++)
			s->kb_string[i] = (rnd_modulo_u32(94)) + 33;	/* printable ASCII */
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
	memset(d, 0, sizeof(*d));
	cnt = rnd_modulo_u32(256);
	d->kb_cnt = cnt;
	for (i = 0; i < cnt; i++) {
		d->kbdiacr[i].diacr  = rnd_u32() & 0xff;
		d->kbdiacr[i].base   = rnd_u32() & 0xff;
		d->kbdiacr[i].result = rnd_u32() & 0xff;
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
	memset(d, 0, sizeof(*d));
	cnt = rnd_modulo_u32(256);
	d->kb_cnt = cnt;
	for (i = 0; i < cnt; i++) {
		d->kbdiacruc[i].diacr  = rnd_u32();
		d->kbdiacruc[i].base   = rnd_u32();
		d->kbdiacruc[i].result = rnd_u32();
	}
	rec->a3 = (unsigned long) d;
}

static void sanitise_vt_kbkeycode(struct syscallrecord *rec)
{
	struct kbkeycode *k;

	k = get_writable_struct(sizeof(*k));
	if (!k)
		return;
	memset(k, 0, sizeof(*k));
	k->scancode = rnd_u32();
	k->keycode  = rnd_modulo_u32(256);
	rec->a3 = (unsigned long) k;
}

static void sanitise_vt_kbd_repeat(struct syscallrecord *rec)
{
	struct kbd_repeat *r;

	r = get_writable_struct(sizeof(*r));
	if (!r)
		return;
	memset(r, 0, sizeof(*r));
	r->delay  = rnd_modulo_u32(1000) + 1;	/* 1-1000 ms */
	r->period = rnd_modulo_u32(500)  + 1;	/* 1-500 ms */
	rec->a3 = (unsigned long) r;
}

/* KD* family */
void vt_sanitise_kd(struct syscallrecord *rec)
{
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
		rec->a3 = rnd_u32() & (LED_SCR | LED_NUM | LED_CAP);
		break;

	/* scalar arg: mode */
	case KDSETMODE:
		rec->a3 = RAND_ARRAY(kd_mode_vals);
		break;

	/* scalar arg: keyboard mode */
	case KDSKBMODE:
		rec->a3 = RAND_ARRAY(kd_kbmode_vals);
		break;

	/* scalar arg: meta handling mode */
	case KDSKBMETA:
		rec->a3 = RAND_BOOL() ? K_METABIT : K_ESCPREFIX;
		break;

	/* scalar arg: led flags */
	case KDSKBLED:
		rec->a3 = rnd_u32() & (K_SCROLLLOCK | K_NUMLOCK | K_CAPSLOCK);
		break;

	/* scalar arg: I/O port number */
	case KDADDIO:
	case KDDELIO:
		rec->a3 = rnd_modulo_u32(0x3ff) + 1;	/* low I/O port range */
		break;

	/* scalar arg: sound frequency (Hz) or 0 for off */
	case KIOCSOUND:
		rec->a3 = RAND_BOOL() ? 0 : (rnd_modulo_u32(4000) + 200);
		break;

	/* scalar arg: frequency and duration packed */
	case KDMKTONE:
		rec->a3 = ((rnd_modulo_u32(4000) + 200) & 0xffff) |
			  ((rnd_modulo_u32(2000)) << 16);
		break;

	/* scalar arg: signal number */
	case KDSIGACCEPT:
		rec->a3 = rnd_modulo_u32(32) + 1;
		break;

	default:
		break;
	}
}
