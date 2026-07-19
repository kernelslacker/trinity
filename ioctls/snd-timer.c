
#include <inttypes.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <sound/asound.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "snd-internal.h"
#include "utils.h"

/* timer */
IOCTL_SIZE_ASSERT(SNDRV_TIMER_IOCTL_NEXT_DEVICE, struct snd_timer_id);
IOCTL_SIZE_ASSERT(SNDRV_TIMER_IOCTL_GINFO, struct snd_timer_ginfo);
IOCTL_SIZE_ASSERT(SNDRV_TIMER_IOCTL_GPARAMS, struct snd_timer_gparams);
IOCTL_SIZE_ASSERT(SNDRV_TIMER_IOCTL_GSTATUS, struct snd_timer_gstatus);
IOCTL_SIZE_ASSERT(SNDRV_TIMER_IOCTL_SELECT, struct snd_timer_select);
IOCTL_SIZE_ASSERT(SNDRV_TIMER_IOCTL_INFO, struct snd_timer_info);
IOCTL_SIZE_ASSERT(SNDRV_TIMER_IOCTL_STATUS, struct snd_timer_status);
IOCTL_SIZE_ASSERT(SNDRV_TIMER_IOCTL_PARAMS, struct snd_timer_params);
#ifdef SNDRV_TIMER_IOCTL_CREATE
IOCTL_SIZE_ASSERT(SNDRV_TIMER_IOCTL_CREATE, struct snd_timer_uinfo);
#endif

static const int snd_timer_class_vals[] = {
	SNDRV_TIMER_CLASS_NONE,
	SNDRV_TIMER_CLASS_SLAVE,
	SNDRV_TIMER_CLASS_GLOBAL,
	SNDRV_TIMER_CLASS_CARD,
	SNDRV_TIMER_CLASS_PCM,
};

void fill_snd_timer_id(struct snd_timer_id *tid)
{
	tid->dev_class = RAND_ARRAY(snd_timer_class_vals);
	tid->dev_sclass = rnd_modulo_u32(4);
	tid->card = RAND_BOOL() ? -1 : (int)(rnd_modulo_u32(8));
	tid->device = RAND_BOOL() ? -1 : (int)(rnd_modulo_u32(32));
	tid->subdevice = rnd_modulo_u32(8);
}

static void snd_timer_sanitise_next_device(struct syscallrecord *rec)
{
	struct snd_timer_id *tid = get_writable_struct(sizeof(*tid));
	if (tid) {
		memset(tid, 0, sizeof(*tid));
		fill_snd_timer_id(tid);
		rec->a3 = (unsigned long) tid;
	}
}

static void snd_timer_sanitise_ginfo(struct syscallrecord *rec)
{
	struct snd_timer_ginfo *gi = get_writable_struct(sizeof(*gi));
	if (gi) {
		memset(gi, 0, sizeof(*gi));
		fill_snd_timer_id(&gi->tid);
		rec->a3 = (unsigned long) gi;
	}
}

static void snd_timer_sanitise_gparams(struct syscallrecord *rec)
{
	struct snd_timer_gparams *gp = get_writable_struct(sizeof(*gp));
	if (gp) {
		memset(gp, 0, sizeof(*gp));
		fill_snd_timer_id(&gp->tid);
		gp->period_num = rnd_modulo_u32(1000000) + 1;
		gp->period_den = rnd_modulo_u32(1000000) + 1;
		rec->a3 = (unsigned long) gp;
	}
}

static void snd_timer_sanitise_gstatus(struct syscallrecord *rec)
{
	struct snd_timer_gstatus *gs = get_writable_struct(sizeof(*gs));
	if (gs) {
		memset(gs, 0, sizeof(*gs));
		fill_snd_timer_id(&gs->tid);
		rec->a3 = (unsigned long) gs;
	}
}

static void snd_timer_sanitise_select(struct syscallrecord *rec)
{
	struct snd_timer_select *sel = get_writable_struct(sizeof(*sel));
	if (sel) {
		memset(sel, 0, sizeof(*sel));
		fill_snd_timer_id(&sel->id);
		rec->a3 = (unsigned long) sel;
	}
}

static void snd_timer_sanitise_info(struct syscallrecord *rec)
{
	struct snd_timer_info *info = get_writable_struct(sizeof(*info));
	if (info) {
		memset(info, 0, sizeof(*info));
		rec->a3 = (unsigned long) info;
	}
}

static void snd_timer_sanitise_status(struct syscallrecord *rec)
{
	struct snd_timer_status *st = get_writable_struct(sizeof(*st));
	if (st) {
		memset(st, 0, sizeof(*st));
		rec->a3 = (unsigned long) st;
	}
}

static void snd_timer_sanitise_params(struct syscallrecord *rec)
{
	struct snd_timer_params *p = get_writable_struct(sizeof(*p));
	if (p) {
		memset(p, 0, sizeof(*p));
		p->flags = rnd_u32() & 0x7;
		p->ticks = rnd_modulo_u32(64) + 1;
		p->queue_size = rnd_modulo_u32((1024 - 32)) + 32;
		p->filter = ~0U;	/* all events */
		rec->a3 = (unsigned long) p;
	}
}

static void snd_timer_sanitise_tread(struct syscallrecord *rec)
{
	int *tread = get_writable_struct(sizeof(int));
	if (tread) {
		*tread = RAND_BOOL();
		rec->a3 = (unsigned long) tread;
	}
}

#ifdef SNDRV_TIMER_IOCTL_CREATE
static void snd_timer_sanitise_create(struct syscallrecord *rec)
{
	struct snd_timer_uinfo *ui = get_writable_struct(sizeof(*ui));
	if (ui) {
		memset(ui, 0, sizeof(*ui));
		ui->resolution = (rnd_modulo_u32(1000000ULL) + 1) * 1000ULL;
		ui->fd = -1;
		ui->id = rnd_modulo_u32(256);
		rec->a3 = (unsigned long) ui;
	}
}
#endif

void sanitise_snd_timer(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_TIMER_IOCTL_NEXT_DEVICE:
		snd_timer_sanitise_next_device(rec);
		break;
	case SNDRV_TIMER_IOCTL_GINFO:
		snd_timer_sanitise_ginfo(rec);
		break;
	case SNDRV_TIMER_IOCTL_GPARAMS:
		snd_timer_sanitise_gparams(rec);
		break;
	case SNDRV_TIMER_IOCTL_GSTATUS:
		snd_timer_sanitise_gstatus(rec);
		break;
	case SNDRV_TIMER_IOCTL_SELECT:
		snd_timer_sanitise_select(rec);
		break;
	case SNDRV_TIMER_IOCTL_INFO:
		snd_timer_sanitise_info(rec);
		break;
	case SNDRV_TIMER_IOCTL_STATUS:
		snd_timer_sanitise_status(rec);
		break;
	case SNDRV_TIMER_IOCTL_PARAMS:
		snd_timer_sanitise_params(rec);
		break;
	case SNDRV_TIMER_IOCTL_TREAD:
#if defined(SNDRV_TIMER_IOCTL_TREAD64) && __BITS_PER_LONG == 64
	case SNDRV_TIMER_IOCTL_TREAD64:
#endif
		snd_timer_sanitise_tread(rec);
		break;
#ifdef SNDRV_TIMER_IOCTL_CREATE
	case SNDRV_TIMER_IOCTL_CREATE:
		snd_timer_sanitise_create(rec);
		break;
#endif
	default:
		break;
	}
}

int dispatch_snd_timer(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_TIMER_IOCTL_NEXT_DEVICE:
	case SNDRV_TIMER_IOCTL_TREAD:
#if defined(SNDRV_TIMER_IOCTL_TREAD64) && __BITS_PER_LONG == 64
	case SNDRV_TIMER_IOCTL_TREAD64:
#endif
#ifdef SNDRV_TIMER_IOCTL_CREATE
	case SNDRV_TIMER_IOCTL_CREATE:
#endif
	case SNDRV_TIMER_IOCTL_GINFO:
	case SNDRV_TIMER_IOCTL_GPARAMS:
	case SNDRV_TIMER_IOCTL_GSTATUS:
	case SNDRV_TIMER_IOCTL_SELECT:
	case SNDRV_TIMER_IOCTL_INFO:
	case SNDRV_TIMER_IOCTL_PARAMS:
	case SNDRV_TIMER_IOCTL_STATUS:
		sanitise_snd_timer(rec);
		return 1;
	}
	return 0;
}
