#include <sys/ioctl.h>
#include <linux/serial.h>
#include <linux/tty.h>
#include <termios.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"
#include "vt-internal.h"

/*
 * Compile-time: sanitise_vt_termios2() fills a struct termios2 whose
 * shape must match the _IOC_SIZE the TCGETS2 family encodes.  The
 * bare-numeric TIOC ioctls dispatched elsewhere (TCGETS, TCSETS,
 * TIOCGWINSZ, ...) carry no size in their request bits
 * (_IOC_SIZE(x) == 0) and are intentionally absent -- a static assert
 * against them would compare sizeof(struct) to 0.
 */
#if defined(TCGETS2)
IOCTL_SIZE_ASSERT(TCGETS2, struct termios2);
#endif
#if defined(TCSETS2)
IOCTL_SIZE_ASSERT(TCSETS2, struct termios2);
#endif
#if defined(TCSETSW2)
IOCTL_SIZE_ASSERT(TCSETSW2, struct termios2);
#endif
#if defined(TCSETSF2)
IOCTL_SIZE_ASSERT(TCSETSF2, struct termios2);
#endif

/*
 * Line-discipline numbers the kernel actually knows about.  Not every
 * kernel has every N_* symbol, so gate the newer ones on the header.
 * A raw modulo-16 draw used to cap coverage at N_TTY..N_HCI and never
 * exercised the modern disciplines (SLCAN, PPS, MCTP, ...).
 */
static const unsigned int n_ldisc_vals[] = {
	N_TTY, N_SLIP, N_MOUSE, N_PPP, N_STRIP,
	N_AX25, N_X25, N_6PACK, N_MASC, N_R3964,
	N_PROFIBUS_FDL, N_IRDA, N_SMSBLOCK, N_HDLC, N_SYNC_PPP,
	N_HCI,
#ifdef N_GIGASET_M101
	N_GIGASET_M101,
#endif
#ifdef N_SLCAN
	N_SLCAN,
#endif
#ifdef N_PPS
	N_PPS,
#endif
#ifdef N_V253
	N_V253,
#endif
#ifdef N_CAIF
	N_CAIF,
#endif
#ifdef N_GSM0710
	N_GSM0710,
#endif
#ifdef N_TI_WL
	N_TI_WL,
#endif
#ifdef N_TRACESINK
	N_TRACESINK,
#endif
#ifdef N_TRACEROUTER
	N_TRACEROUTER,
#endif
#ifdef N_NCI
	N_NCI,
#endif
#ifdef N_SPEAKUP
	N_SPEAKUP,
#endif
#ifdef N_NULL
	N_NULL,
#endif
#ifdef N_MCTP
	N_MCTP,
#endif
};

/* TIOC* and termios family */

static void fill_termios_flags(tcflag_t *iflag, tcflag_t *oflag,
				tcflag_t *cflag, tcflag_t *lflag)
{
	/* baud rates: B50 through B4000000 (powers of two index into B* constants) */
	static const tcflag_t baud_rates[] = {
		B50, B75, B110, B134, B150, B200, B300, B600,
		B1200, B1800, B2400, B4800, B9600, B19200, B38400,
		B57600, B115200, B230400,
	};
	tcflag_t baud = baud_rates[rnd_modulo_u32(ARRAY_SIZE(baud_rates))];

	*iflag = rnd_u32() & (IGNBRK|BRKINT|IGNPAR|PARMRK|INPCK|ISTRIP|
			   INLCR|IGNCR|ICRNL|IXON|IXANY|IXOFF|IMAXBEL);
	*oflag = rnd_u32() & (OPOST|ONLCR|OCRNL|ONOCR|ONLRET|OFILL);
	*cflag = baud | (RAND_BOOL() ? CS8 : CS7) | CREAD |
		 (RAND_BOOL() ? PARENB : 0) | (RAND_BOOL() ? CLOCAL : 0);
	*lflag = rnd_u32() & (ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHONL|
			   NOFLSH|TOSTOP|IEXTEN);
}

static void sanitise_vt_termios(struct syscallrecord *rec)
{
	struct termios *t;

	t = get_writable_struct(sizeof(*t));
	if (!t)
		return;
	memset(t, 0, sizeof(*t));
	fill_termios_flags(&t->c_iflag, &t->c_oflag, &t->c_cflag, &t->c_lflag);
	t->c_line = RAND_ARRAY(n_ldisc_vals);
	rec->a3 = (unsigned long) t;
}

static void sanitise_vt_termios2(struct syscallrecord *rec)
{
	struct termios2 *t;

	t = get_writable_struct(sizeof(*t));
	if (!t)
		return;
	memset(t, 0, sizeof(*t));
	fill_termios_flags(&t->c_iflag, &t->c_oflag, &t->c_cflag, &t->c_lflag);
	t->c_line   = RAND_ARRAY(n_ldisc_vals);
	t->c_ispeed = rnd_modulo_u32(4000000) + 50;
	t->c_ospeed = rnd_modulo_u32(4000000) + 50;
	rec->a3 = (unsigned long) t;
}

static void sanitise_vt_winsize(struct syscallrecord *rec)
{
	struct winsize *w;
	unsigned short rows, cols;

	w = get_writable_struct(sizeof(*w));
	if (!w)
		return;
	memset(w, 0, sizeof(*w));
	rows = rnd_modulo_u32(200) + 1;
	cols = rnd_modulo_u32(300) + 1;
	w->ws_row    = rows;
	w->ws_col    = cols;
	w->ws_xpixel = cols * (rnd_modulo_u32(8) + 8);
	w->ws_ypixel = rows * (rnd_modulo_u32(8) + 8);
	rec->a3 = (unsigned long) w;
}

static void sanitise_vt_serial_struct(struct syscallrecord *rec)
{
	struct serial_struct *s;

	s = get_writable_struct(sizeof(*s));
	if (!s)
		return;
	memset(s, 0, sizeof(*s));
	s->type            = rnd_modulo_u32(16);
	s->line            = rnd_modulo_u32(64);
	s->port            = rnd_modulo_u32(0x400);
	s->irq             = rnd_modulo_u32(16);
	s->flags           = rnd_u32() & 0x7ffffff;
	s->xmit_fifo_size  = rnd_modulo_u32(256);
	s->custom_divisor  = rnd_modulo_u32(256) + 1;
	s->baud_base       = rnd_modulo_u32(115200) + 1200;
	s->close_delay     = rnd_modulo_u32(500);
	s->closing_wait    = RAND_BOOL() ? 65535 : rnd_modulo_u32(3000);
	rec->a3 = (unsigned long) s;
}

/* TIOC* and termios family */
void vt_sanitise_tioc(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case TCGETS:
	case TCSETS:
	case TCSETSW:
	case TCSETSF:
	case TCGETA:
	case TCSETA:
	case TCSETAW:
	case TCSETAF:
	case TIOCGLCKTRMIOS:
	case TIOCSLCKTRMIOS:
		sanitise_vt_termios(rec);
		break;

#ifdef TCGETS2
	case TCGETS2:
#endif
#ifdef TCSETS2
	case TCSETS2:
#endif
#ifdef TCSETSW2
	case TCSETSW2:
#endif
#ifdef TCSETSF2
	case TCSETSF2:
#endif
#if defined(TCGETS2) || defined(TCSETS2) || defined(TCSETSW2) || defined(TCSETSF2)
		sanitise_vt_termios2(rec);
		break;
#endif

	case TIOCGWINSZ:
	case TIOCSWINSZ:
		sanitise_vt_winsize(rec);
		break;

	case TIOCGSERIAL:
	case TIOCSSERIAL:
		sanitise_vt_serial_struct(rec);
		break;

	case TIOCSPGRP: {
		pid_t *p = get_writable_struct(sizeof(pid_t));

		if (p) {
			*p = rnd_modulo_u32(65535) + 1;
			rec->a3 = (unsigned long) p;
		}
		break;
	}

	case TIOCMBIS:
	case TIOCMBIC:
	case TIOCMSET: {
		int *bits = get_writable_struct(sizeof(int));

		if (bits) {
			*bits = rnd_u32() & (TIOCM_LE|TIOCM_DTR|TIOCM_RTS|TIOCM_ST|
					  TIOCM_SR|TIOCM_CTS|TIOCM_CAR|TIOCM_RNG|
					  TIOCM_DSR);
			rec->a3 = (unsigned long) bits;
		}
		break;
	}

	case TIOCSPTLCK:
#ifdef TIOCSIG
	case TIOCSIG:
#endif
	case TIOCSSOFTCAR:
	case TIOCPKT:
	case TIOCSETD:
	case FIONBIO:
	case FIOASYNC:
	case TIOCMIWAIT: {
		int *p = get_writable_struct(sizeof(int));

		if (p) {
			*p = rnd_u32();
			rec->a3 = (unsigned long) p;
		}
		break;
	}

	case TCSBRK:
	case TCSBRKP:
	case TCXONC:
	case TCFLSH:
		rec->a3 = rnd_modulo_u32(4);
		break;

	default:
		break;
	}
}
