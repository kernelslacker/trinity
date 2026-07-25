#include <sys/vt.h>
#include <sys/ioctl.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"
#include "vt-internal.h"

/*
 * Compile-time: VT_GETCONSIZECSRPOS -- the sole _IOR-encoded struct
 * command in the VT_* set -- must match struct vt_consizecsrpos.
 * The bare-numeric VT ioctls dispatched elsewhere (VT_GETMODE,
 * VT_SETMODE, ...) carry no size in their request bits
 * (_IOC_SIZE(x) == 0) and are intentionally absent -- a static assert
 * against them would compare sizeof(struct) to 0.
 */
#ifdef VT_GETCONSIZECSRPOS
IOCTL_SIZE_ASSERT(VT_GETCONSIZECSRPOS, struct vt_consizecsrpos);
#endif

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
void vt_sanitise_vt(struct syscallrecord *rec)
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
