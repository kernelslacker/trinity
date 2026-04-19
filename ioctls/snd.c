
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <sound/asound.h>
#include <sound/asound_fm.h>
#include <sound/asequencer.h>
#include <sound/hdsp.h>
#include <sound/hdspm.h>
#include <sound/sb16_csp.h>
#include <sound/sfnt_info.h>
#ifdef USE_SNDDRV_COMPRESS_OFFLOAD
#include <sound/compress_offload.h>
#endif

/* would use this, but the header uses DECLARE_BITMAP() from the kernel */
/* #include <sound/emu10k1.h> */

#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

/* include/sound/hda_hwdep.h */
struct hda_verb_ioctl {
        __u32 verb;       /* HDA_VERB() */
        __u32 res;        /* response */
};
#define HDA_IOCTL_PVERSION              _IOR('H', 0x10, int)
#define HDA_IOCTL_VERB_WRITE            _IOWR('H', 0x11, struct hda_verb_ioctl)
#define HDA_IOCTL_GET_WCAP              _IOWR('H', 0x12, struct hda_verb_ioctl)

static void sanitise_snd_hwdep(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_HWDEP_IOCTL_INFO: {
		struct snd_hwdep_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			info->device = rand() % 8;
			rec->a3 = (unsigned long) info;
		}
		break;
	}
	case SNDRV_HWDEP_IOCTL_DSP_STATUS: {
		struct snd_hwdep_dsp_status *st = get_writable_struct(sizeof(*st));
		if (st)
			rec->a3 = (unsigned long) st;
		break;
	}
	case SNDRV_HWDEP_IOCTL_DSP_LOAD: {
		struct snd_hwdep_dsp_image *img = get_writable_struct(sizeof(*img));
		if (img) {
			img->index = rand() % 8;
			img->length = rand() % 4096 + 1;
			img->image = get_writable_struct(img->length);
			rec->a3 = (unsigned long) img;
		}
		break;
	}
	default:
		break;
	}
}

static void fill_snd_ctl_elem_id(struct snd_ctl_elem_id *id)
{
	id->numid = RAND_BOOL() ? 0 : rand() % 64;
	id->iface = rand() % 7;		/* SNDRV_CTL_ELEM_IFACE_* 0-6 */
	id->device = rand() % 8;
	id->subdevice = rand() % 8;
	id->index = rand() % 8;
}

static void sanitise_snd_ctl(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_CTL_IOCTL_CARD_INFO: {
		struct snd_ctl_card_info *info = get_writable_struct(sizeof(*info));
		if (info)
			rec->a3 = (unsigned long) info;
		break;
	}
	case SNDRV_CTL_IOCTL_ELEM_LIST: {
		struct snd_ctl_elem_list *list = get_writable_struct(sizeof(*list));
		if (list) {
			unsigned int space = rand() % 16 + 1;
			list->offset = rand() % 64;
			list->space = space;
			list->pids = get_writable_struct(space * sizeof(*list->pids));
			rec->a3 = (unsigned long) list;
		}
		break;
	}
	case SNDRV_CTL_IOCTL_ELEM_INFO:
	case SNDRV_CTL_IOCTL_ELEM_ADD:
	case SNDRV_CTL_IOCTL_ELEM_REPLACE: {
		struct snd_ctl_elem_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			fill_snd_ctl_elem_id(&info->id);
			rec->a3 = (unsigned long) info;
		}
		break;
	}
	case SNDRV_CTL_IOCTL_ELEM_READ:
	case SNDRV_CTL_IOCTL_ELEM_WRITE: {
		struct snd_ctl_elem_value *val = get_writable_struct(sizeof(*val));
		if (val) {
			fill_snd_ctl_elem_id(&val->id);
			rec->a3 = (unsigned long) val;
		}
		break;
	}
	case SNDRV_CTL_IOCTL_ELEM_LOCK:
	case SNDRV_CTL_IOCTL_ELEM_UNLOCK:
	case SNDRV_CTL_IOCTL_ELEM_REMOVE: {
		struct snd_ctl_elem_id *id = get_writable_struct(sizeof(*id));
		if (id) {
			fill_snd_ctl_elem_id(id);
			rec->a3 = (unsigned long) id;
		}
		break;
	}
	case SNDRV_CTL_IOCTL_TLV_READ:
	case SNDRV_CTL_IOCTL_TLV_WRITE:
	case SNDRV_CTL_IOCTL_TLV_COMMAND: {
		unsigned int datalen = (rand() % 8 + 1) * 4;
		/* snd_ctl_tlv has a flexible array member, allocate with data */
		struct snd_ctl_tlv *tlv = get_writable_struct(sizeof(*tlv) + datalen);
		if (tlv) {
			tlv->numid = rand() % 64;
			tlv->length = datalen;
			rec->a3 = (unsigned long) tlv;
		}
		break;
	}
	case SNDRV_CTL_IOCTL_HWDEP_NEXT_DEVICE:
	case SNDRV_CTL_IOCTL_PCM_NEXT_DEVICE:
	case SNDRV_CTL_IOCTL_RAWMIDI_NEXT_DEVICE: {
		int *dev = get_writable_struct(sizeof(int));
		if (dev) {
			*dev = (int)(rand() % 8) - 1;	/* -1 to get first, 0-7 otherwise */
			rec->a3 = (unsigned long) dev;
		}
		break;
	}
	case SNDRV_CTL_IOCTL_HWDEP_INFO: {
		struct snd_hwdep_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			info->device = rand() % 8;
			rec->a3 = (unsigned long) info;
		}
		break;
	}
	case SNDRV_CTL_IOCTL_PCM_INFO: {
		struct snd_pcm_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			info->device = rand() % 8;
			info->subdevice = rand() % 8;
			info->stream = rand() & 1;
			rec->a3 = (unsigned long) info;
		}
		break;
	}
	case SNDRV_CTL_IOCTL_RAWMIDI_INFO: {
		struct snd_rawmidi_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			info->device = rand() % 8;
			info->subdevice = rand() % 8;
			info->stream = rand() % 3;
			rec->a3 = (unsigned long) info;
		}
		break;
	}
	case SNDRV_CTL_IOCTL_PCM_PREFER_SUBDEVICE:
	case SNDRV_CTL_IOCTL_RAWMIDI_PREFER_SUBDEVICE:
	case SNDRV_CTL_IOCTL_POWER: {
		int *val = get_writable_struct(sizeof(int));
		if (val) {
			*val = rand() % 8;
			rec->a3 = (unsigned long) val;
		}
		break;
	}
	case SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS: {
		int *sub = get_writable_struct(sizeof(int));
		if (sub) {
			*sub = RAND_BOOL();
			rec->a3 = (unsigned long) sub;
		}
		break;
	}
	default:
		break;
	}
}

static const unsigned int pcm_rates[] = {
	8000, 11025, 16000, 22050, 32000, 44100, 48000, 64000, 88200, 96000, 192000,
};

static void fill_snd_pcm_hw_params(struct snd_pcm_hw_params *p)
{
	unsigned int rate;
	unsigned int channels;
	/* index within intervals[]: param - SNDRV_PCM_HW_PARAM_FIRST_INTERVAL */
	unsigned int rate_idx = SNDRV_PCM_HW_PARAM_RATE - SNDRV_PCM_HW_PARAM_FIRST_INTERVAL;
	unsigned int chan_idx = SNDRV_PCM_HW_PARAM_CHANNELS - SNDRV_PCM_HW_PARAM_FIRST_INTERVAL;

	rate = pcm_rates[rand() % ARRAY_SIZE(pcm_rates)];
	channels = rand() % 8 + 1;

	p->rmask = ~0U;		/* request all params */
	p->intervals[rate_idx].min = rate;
	p->intervals[rate_idx].max = rate;
	p->intervals[rate_idx].integer = 1;
	p->intervals[chan_idx].min = channels;
	p->intervals[chan_idx].max = channels;
	p->intervals[chan_idx].integer = 1;
	/* leave format mask zero: kernel will open it up */
}

static void sanitise_snd_pcm(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_PCM_IOCTL_INFO: {
		struct snd_pcm_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			info->device = rand() % 8;
			info->subdevice = rand() % 8;
			info->stream = rand() & 1;
			rec->a3 = (unsigned long) info;
		}
		break;
	}
	case SNDRV_PCM_IOCTL_TSTAMP:
	case SNDRV_PCM_IOCTL_TTSTAMP: {
		int *mode = get_writable_struct(sizeof(int));
		if (mode) {
			*mode = rand() % 3;
			rec->a3 = (unsigned long) mode;
		}
		break;
	}
	case SNDRV_PCM_IOCTL_HW_REFINE:
	case SNDRV_PCM_IOCTL_HW_PARAMS: {
		struct snd_pcm_hw_params *p = get_writable_struct(sizeof(*p));
		if (p) {
			fill_snd_pcm_hw_params(p);
			rec->a3 = (unsigned long) p;
		}
		break;
	}
	case SNDRV_PCM_IOCTL_SW_PARAMS: {
		struct snd_pcm_sw_params *p = get_writable_struct(sizeof(*p));
		if (p) {
			p->avail_min = rand() % 4096 + 1;
			p->start_threshold = rand() % 8192 + 1;
			p->stop_threshold = rand() % 8192 + 1;
			p->tstamp_mode = rand() % 2;
			p->period_step = 1;
			rec->a3 = (unsigned long) p;
		}
		break;
	}
	case SNDRV_PCM_IOCTL_STATUS: {
		struct snd_pcm_status *st = get_writable_struct(sizeof(*st));
		if (st)
			rec->a3 = (unsigned long) st;
		break;
	}
	case SNDRV_PCM_IOCTL_DELAY: {
		snd_pcm_sframes_t *delay = get_writable_struct(sizeof(*delay));
		if (delay)
			rec->a3 = (unsigned long) delay;
		break;
	}
	case SNDRV_PCM_IOCTL_CHANNEL_INFO: {
		struct snd_pcm_channel_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			info->channel = rand() % 8;
			rec->a3 = (unsigned long) info;
		}
		break;
	}
	case SNDRV_PCM_IOCTL_SYNC_PTR: {
		struct snd_pcm_sync_ptr *sp = get_writable_struct(sizeof(*sp));
		if (sp)
			rec->a3 = (unsigned long) sp;
		break;
	}
	case SNDRV_PCM_IOCTL_WRITEI_FRAMES:
	case SNDRV_PCM_IOCTL_READI_FRAMES: {
		struct snd_xferi *xfer = get_writable_struct(sizeof(*xfer));
		if (xfer) {
			unsigned int frames = rand() % 1024 + 1;
			xfer->frames = frames;
			xfer->buf = get_writable_struct(frames * 8);	/* up to 8 bytes/frame */
			rec->a3 = (unsigned long) xfer;
		}
		break;
	}
	case SNDRV_PCM_IOCTL_WRITEN_FRAMES:
	case SNDRV_PCM_IOCTL_READN_FRAMES: {
		struct snd_xfern *xfer = get_writable_struct(sizeof(*xfer));
		if (xfer) {
			unsigned int frames = rand() % 1024 + 1;
			unsigned int channels = rand() % 8 + 1;
			unsigned int i;
			xfer->frames = frames;
			xfer->bufs = get_writable_struct(channels * sizeof(void *));
			for (i = 0; xfer->bufs && i < channels; i++)
				xfer->bufs[i] = get_writable_struct(frames * 4);
			rec->a3 = (unsigned long) xfer;
		}
		break;
	}
	case SNDRV_PCM_IOCTL_LINK: {
		int *fd = get_writable_struct(sizeof(int));
		if (fd) {
			*fd = rand() % 1024;
			rec->a3 = (unsigned long) fd;
		}
		break;
	}
	default:
		break;
	}
}

static void sanitise_snd_rawmidi(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_RAWMIDI_IOCTL_INFO: {
		struct snd_rawmidi_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			info->device = rand() % 8;
			info->subdevice = rand() % 8;
			info->stream = rand() % 3;
			rec->a3 = (unsigned long) info;
		}
		break;
	}
	case SNDRV_RAWMIDI_IOCTL_PARAMS: {
		struct snd_rawmidi_params *p = get_writable_struct(sizeof(*p));
		if (p) {
			p->stream = rand() & 1;
			p->buffer_size = (rand() % 16 + 1) * 4096;
			p->avail_min = rand() % 256 + 1;
			rec->a3 = (unsigned long) p;
		}
		break;
	}
	case SNDRV_RAWMIDI_IOCTL_STATUS: {
		struct snd_rawmidi_status *st = get_writable_struct(sizeof(*st));
		if (st) {
			st->stream = rand() & 1;
			rec->a3 = (unsigned long) st;
		}
		break;
	}
	case SNDRV_RAWMIDI_IOCTL_DROP:
	case SNDRV_RAWMIDI_IOCTL_DRAIN: {
		int *stream = get_writable_struct(sizeof(int));
		if (stream) {
			*stream = rand() & 1;
			rec->a3 = (unsigned long) stream;
		}
		break;
	}
	default:
		break;
	}
}

static void fill_snd_timer_id(struct snd_timer_id *tid)
{
	tid->dev_class = (int)(rand() % 4) - 1;	/* -1 (none) to 3 (PCM) */
	tid->dev_sclass = rand() % 4;
	tid->card = RAND_BOOL() ? -1 : (int)(rand() % 8);
	tid->device = RAND_BOOL() ? -1 : (int)(rand() % 32);
	tid->subdevice = rand() % 8;
}

static void sanitise_snd_timer(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_TIMER_IOCTL_NEXT_DEVICE: {
		struct snd_timer_id *tid = get_writable_struct(sizeof(*tid));
		if (tid) {
			fill_snd_timer_id(tid);
			rec->a3 = (unsigned long) tid;
		}
		break;
	}
	case SNDRV_TIMER_IOCTL_GINFO: {
		struct snd_timer_ginfo *gi = get_writable_struct(sizeof(*gi));
		if (gi) {
			fill_snd_timer_id(&gi->tid);
			rec->a3 = (unsigned long) gi;
		}
		break;
	}
	case SNDRV_TIMER_IOCTL_GPARAMS: {
		struct snd_timer_gparams *gp = get_writable_struct(sizeof(*gp));
		if (gp) {
			fill_snd_timer_id(&gp->tid);
			gp->period_num = rand() % 1000000 + 1;
			gp->period_den = rand() % 1000000 + 1;
			rec->a3 = (unsigned long) gp;
		}
		break;
	}
	case SNDRV_TIMER_IOCTL_GSTATUS: {
		struct snd_timer_gstatus *gs = get_writable_struct(sizeof(*gs));
		if (gs) {
			fill_snd_timer_id(&gs->tid);
			rec->a3 = (unsigned long) gs;
		}
		break;
	}
	case SNDRV_TIMER_IOCTL_SELECT: {
		struct snd_timer_select *sel = get_writable_struct(sizeof(*sel));
		if (sel) {
			fill_snd_timer_id(&sel->id);
			rec->a3 = (unsigned long) sel;
		}
		break;
	}
	case SNDRV_TIMER_IOCTL_INFO: {
		struct snd_timer_info *info = get_writable_struct(sizeof(*info));
		if (info)
			rec->a3 = (unsigned long) info;
		break;
	}
	case SNDRV_TIMER_IOCTL_STATUS: {
		struct snd_timer_status *st = get_writable_struct(sizeof(*st));
		if (st)
			rec->a3 = (unsigned long) st;
		break;
	}
	case SNDRV_TIMER_IOCTL_PARAMS: {
		struct snd_timer_params *p = get_writable_struct(sizeof(*p));
		if (p) {
			p->flags = rand() & 0x7;
			p->ticks = rand() % 64 + 1;
			p->queue_size = rand() % (1024 - 32) + 32;
			p->filter = ~0U;	/* all events */
			rec->a3 = (unsigned long) p;
		}
		break;
	}
	case SNDRV_TIMER_IOCTL_TREAD: {
		int *tread = get_writable_struct(sizeof(int));
		if (tread) {
			*tread = RAND_BOOL();
			rec->a3 = (unsigned long) tread;
		}
		break;
	}
	default:
		break;
	}
}

static void fill_snd_seq_addr(struct snd_seq_addr *addr)
{
	addr->client = rand() % 128;
	addr->port = rand() % 256;
}

static void sanitise_snd_seq(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_SEQ_IOCTL_SYSTEM_INFO: {
		struct snd_seq_system_info *info = get_writable_struct(sizeof(*info));
		if (info)
			rec->a3 = (unsigned long) info;
		break;
	}
	case SNDRV_SEQ_IOCTL_RUNNING_MODE: {
		struct snd_seq_running_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			info->client = rand() % 128;
			rec->a3 = (unsigned long) info;
		}
		break;
	}
	case SNDRV_SEQ_IOCTL_GET_CLIENT_INFO:
	case SNDRV_SEQ_IOCTL_SET_CLIENT_INFO:
	case SNDRV_SEQ_IOCTL_QUERY_NEXT_CLIENT: {
		struct snd_seq_client_info *ci = get_writable_struct(sizeof(*ci));
		if (ci) {
			ci->client = RAND_BOOL() ? -1 : (int)(rand() % 128);
			rec->a3 = (unsigned long) ci;
		}
		break;
	}
	case SNDRV_SEQ_IOCTL_CREATE_PORT:
	case SNDRV_SEQ_IOCTL_DELETE_PORT:
	case SNDRV_SEQ_IOCTL_GET_PORT_INFO:
	case SNDRV_SEQ_IOCTL_SET_PORT_INFO:
	case SNDRV_SEQ_IOCTL_QUERY_NEXT_PORT: {
		struct snd_seq_port_info *pi = get_writable_struct(sizeof(*pi));
		if (pi) {
			fill_snd_seq_addr(&pi->addr);
			if (rec->a2 == SNDRV_SEQ_IOCTL_QUERY_NEXT_PORT)
				pi->addr.port = (unsigned char)(rand() % 256) - 1;
			pi->capability = rand();
			pi->type = rand();
			pi->midi_channels = rand() % 16 + 1;
			rec->a3 = (unsigned long) pi;
		}
		break;
	}
	case SNDRV_SEQ_IOCTL_SUBSCRIBE_PORT:
	case SNDRV_SEQ_IOCTL_UNSUBSCRIBE_PORT:
	case SNDRV_SEQ_IOCTL_GET_SUBSCRIPTION: {
		struct snd_seq_port_subscribe *sub = get_writable_struct(sizeof(*sub));
		if (sub) {
			fill_snd_seq_addr(&sub->sender);
			fill_snd_seq_addr(&sub->dest);
			rec->a3 = (unsigned long) sub;
		}
		break;
	}
	case SNDRV_SEQ_IOCTL_CREATE_QUEUE:
	case SNDRV_SEQ_IOCTL_DELETE_QUEUE:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_INFO:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_INFO:
	case SNDRV_SEQ_IOCTL_GET_NAMED_QUEUE: {
		struct snd_seq_queue_info *qi = get_writable_struct(sizeof(*qi));
		if (qi) {
			qi->queue = rand() % 8;
			qi->owner = rand() % 128;
			rec->a3 = (unsigned long) qi;
		}
		break;
	}
	case SNDRV_SEQ_IOCTL_GET_QUEUE_STATUS: {
		struct snd_seq_queue_status *qs = get_writable_struct(sizeof(*qs));
		if (qs) {
			qs->queue = rand() % 8;
			rec->a3 = (unsigned long) qs;
		}
		break;
	}
	case SNDRV_SEQ_IOCTL_GET_QUEUE_TEMPO:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_TEMPO: {
		struct snd_seq_queue_tempo *qt = get_writable_struct(sizeof(*qt));
		if (qt) {
			qt->queue = rand() % 8;
			qt->tempo = rand() % 2000000 + 60000;	/* 60ms-2s per beat */
			qt->ppq = rand() % 480 + 24;
			rec->a3 = (unsigned long) qt;
		}
		break;
	}
	case SNDRV_SEQ_IOCTL_GET_QUEUE_TIMER:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_TIMER: {
		struct snd_seq_queue_timer *timer = get_writable_struct(sizeof(*timer));
		if (timer) {
			timer->queue = rand() % 8;
			timer->type = rand() % 3;
			fill_snd_timer_id(&timer->u.alsa.id);
			timer->u.alsa.resolution = rand() % 480 + 24;
			rec->a3 = (unsigned long) timer;
		}
		break;
	}
	case SNDRV_SEQ_IOCTL_GET_QUEUE_CLIENT:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_CLIENT: {
		struct snd_seq_queue_client *qc = get_writable_struct(sizeof(*qc));
		if (qc) {
			qc->queue = rand() % 8;
			qc->client = rand() % 128;
			qc->used = RAND_BOOL();
			rec->a3 = (unsigned long) qc;
		}
		break;
	}
	case SNDRV_SEQ_IOCTL_GET_CLIENT_POOL:
	case SNDRV_SEQ_IOCTL_SET_CLIENT_POOL: {
		struct snd_seq_client_pool *cp = get_writable_struct(sizeof(*cp));
		if (cp) {
			cp->client = rand() % 128;
			cp->output_pool = rand() % 1024 + 64;
			cp->input_pool = rand() % 512 + 32;
			cp->output_room = rand() % 64 + 1;
			rec->a3 = (unsigned long) cp;
		}
		break;
	}
	case SNDRV_SEQ_IOCTL_REMOVE_EVENTS: {
		struct snd_seq_remove_events *re = get_writable_struct(sizeof(*re));
		if (re) {
			re->remove_mode = rand() & 0x3ff;
			rec->a3 = (unsigned long) re;
		}
		break;
	}
	case SNDRV_SEQ_IOCTL_QUERY_SUBS: {
		struct snd_seq_query_subs *qs = get_writable_struct(sizeof(*qs));
		if (qs) {
			fill_snd_seq_addr(&qs->root);
			qs->type = rand() & 1;
			qs->index = rand() % 64;
			rec->a3 = (unsigned long) qs;
		}
		break;
	}
	default:
		break;
	}
}

static void sanitise_snd_ump(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_UMP_IOCTL_ENDPOINT_INFO: {
		struct snd_ump_endpoint_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			info->card = rand() % 8;
			info->device = rand() % 8;
			rec->a3 = (unsigned long) info;
		}
		break;
	}
	case SNDRV_UMP_IOCTL_BLOCK_INFO: {
		struct snd_ump_block_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			info->card = rand() % 8;
			info->device = rand() % 8;
			info->block_id = rand() % SNDRV_UMP_MAX_BLOCKS;
			rec->a3 = (unsigned long) info;
		}
		break;
	}
	default:
		break;
	}
}

static void sound_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	/* snd-hwdep */
	case SNDRV_HWDEP_IOCTL_INFO:
	case SNDRV_HWDEP_IOCTL_DSP_STATUS:
	case SNDRV_HWDEP_IOCTL_DSP_LOAD:
		sanitise_snd_hwdep(rec);
		break;

	/* snd-control */
	case SNDRV_CTL_IOCTL_CARD_INFO:
	case SNDRV_CTL_IOCTL_ELEM_LIST:
	case SNDRV_CTL_IOCTL_ELEM_INFO:
	case SNDRV_CTL_IOCTL_ELEM_READ:
	case SNDRV_CTL_IOCTL_ELEM_WRITE:
	case SNDRV_CTL_IOCTL_ELEM_LOCK:
	case SNDRV_CTL_IOCTL_ELEM_UNLOCK:
	case SNDRV_CTL_IOCTL_ELEM_ADD:
	case SNDRV_CTL_IOCTL_ELEM_REPLACE:
	case SNDRV_CTL_IOCTL_ELEM_REMOVE:
	case SNDRV_CTL_IOCTL_TLV_READ:
	case SNDRV_CTL_IOCTL_TLV_WRITE:
	case SNDRV_CTL_IOCTL_TLV_COMMAND:
	case SNDRV_CTL_IOCTL_HWDEP_NEXT_DEVICE:
	case SNDRV_CTL_IOCTL_HWDEP_INFO:
	case SNDRV_CTL_IOCTL_PCM_NEXT_DEVICE:
	case SNDRV_CTL_IOCTL_PCM_INFO:
	case SNDRV_CTL_IOCTL_PCM_PREFER_SUBDEVICE:
	case SNDRV_CTL_IOCTL_RAWMIDI_NEXT_DEVICE:
	case SNDRV_CTL_IOCTL_RAWMIDI_INFO:
	case SNDRV_CTL_IOCTL_RAWMIDI_PREFER_SUBDEVICE:
	case SNDRV_CTL_IOCTL_POWER:
	case SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS:
		sanitise_snd_ctl(rec);
		break;

	/* snd-pcm */
	case SNDRV_PCM_IOCTL_INFO:
	case SNDRV_PCM_IOCTL_TSTAMP:
	case SNDRV_PCM_IOCTL_TTSTAMP:
	case SNDRV_PCM_IOCTL_HW_REFINE:
	case SNDRV_PCM_IOCTL_HW_PARAMS:
	case SNDRV_PCM_IOCTL_SW_PARAMS:
	case SNDRV_PCM_IOCTL_STATUS:
	case SNDRV_PCM_IOCTL_DELAY:
	case SNDRV_PCM_IOCTL_SYNC_PTR:
	case SNDRV_PCM_IOCTL_CHANNEL_INFO:
	case SNDRV_PCM_IOCTL_WRITEI_FRAMES:
	case SNDRV_PCM_IOCTL_READI_FRAMES:
	case SNDRV_PCM_IOCTL_WRITEN_FRAMES:
	case SNDRV_PCM_IOCTL_READN_FRAMES:
	case SNDRV_PCM_IOCTL_LINK:
		sanitise_snd_pcm(rec);
		break;

	/* snd-rawmidi */
	case SNDRV_RAWMIDI_IOCTL_INFO:
	case SNDRV_RAWMIDI_IOCTL_PARAMS:
	case SNDRV_RAWMIDI_IOCTL_STATUS:
	case SNDRV_RAWMIDI_IOCTL_DROP:
	case SNDRV_RAWMIDI_IOCTL_DRAIN:
		sanitise_snd_rawmidi(rec);
		break;

	/* snd-ump */
	case SNDRV_UMP_IOCTL_ENDPOINT_INFO:
	case SNDRV_UMP_IOCTL_BLOCK_INFO:
		sanitise_snd_ump(rec);
		break;

	/* snd-timer */
	case SNDRV_TIMER_IOCTL_NEXT_DEVICE:
	case SNDRV_TIMER_IOCTL_TREAD:
	case SNDRV_TIMER_IOCTL_GINFO:
	case SNDRV_TIMER_IOCTL_GPARAMS:
	case SNDRV_TIMER_IOCTL_GSTATUS:
	case SNDRV_TIMER_IOCTL_SELECT:
	case SNDRV_TIMER_IOCTL_INFO:
	case SNDRV_TIMER_IOCTL_PARAMS:
	case SNDRV_TIMER_IOCTL_STATUS:
		sanitise_snd_timer(rec);
		break;

	/* snd-seq */
	case SNDRV_SEQ_IOCTL_SYSTEM_INFO:
	case SNDRV_SEQ_IOCTL_RUNNING_MODE:
	case SNDRV_SEQ_IOCTL_GET_CLIENT_INFO:
	case SNDRV_SEQ_IOCTL_SET_CLIENT_INFO:
	case SNDRV_SEQ_IOCTL_CREATE_PORT:
	case SNDRV_SEQ_IOCTL_DELETE_PORT:
	case SNDRV_SEQ_IOCTL_GET_PORT_INFO:
	case SNDRV_SEQ_IOCTL_SET_PORT_INFO:
	case SNDRV_SEQ_IOCTL_SUBSCRIBE_PORT:
	case SNDRV_SEQ_IOCTL_UNSUBSCRIBE_PORT:
	case SNDRV_SEQ_IOCTL_CREATE_QUEUE:
	case SNDRV_SEQ_IOCTL_DELETE_QUEUE:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_INFO:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_INFO:
	case SNDRV_SEQ_IOCTL_GET_NAMED_QUEUE:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_STATUS:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_TEMPO:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_TEMPO:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_TIMER:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_TIMER:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_CLIENT:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_CLIENT:
	case SNDRV_SEQ_IOCTL_GET_CLIENT_POOL:
	case SNDRV_SEQ_IOCTL_SET_CLIENT_POOL:
	case SNDRV_SEQ_IOCTL_REMOVE_EVENTS:
	case SNDRV_SEQ_IOCTL_QUERY_SUBS:
	case SNDRV_SEQ_IOCTL_GET_SUBSCRIPTION:
	case SNDRV_SEQ_IOCTL_QUERY_NEXT_CLIENT:
	case SNDRV_SEQ_IOCTL_QUERY_NEXT_PORT:
		sanitise_snd_seq(rec);
		break;

	default:
		break;
	}
}

static const struct ioctl sound_ioctls[] = {
	IOCTL(SNDRV_SEQ_IOCTL_PVERSION),
	IOCTL(SNDRV_SEQ_IOCTL_CLIENT_ID),
	IOCTL(SNDRV_SEQ_IOCTL_SYSTEM_INFO),
	IOCTL(SNDRV_SEQ_IOCTL_RUNNING_MODE),
	IOCTL(SNDRV_SEQ_IOCTL_GET_CLIENT_INFO),
	IOCTL(SNDRV_SEQ_IOCTL_SET_CLIENT_INFO),
	IOCTL(SNDRV_SEQ_IOCTL_CREATE_PORT),
	IOCTL(SNDRV_SEQ_IOCTL_DELETE_PORT),
	IOCTL(SNDRV_SEQ_IOCTL_GET_PORT_INFO),
	IOCTL(SNDRV_SEQ_IOCTL_SET_PORT_INFO),
	IOCTL(SNDRV_SEQ_IOCTL_SUBSCRIBE_PORT),
	IOCTL(SNDRV_SEQ_IOCTL_UNSUBSCRIBE_PORT),
	IOCTL(SNDRV_SEQ_IOCTL_CREATE_QUEUE),
	IOCTL(SNDRV_SEQ_IOCTL_DELETE_QUEUE),
	IOCTL(SNDRV_SEQ_IOCTL_GET_QUEUE_INFO),
	IOCTL(SNDRV_SEQ_IOCTL_SET_QUEUE_INFO),
	IOCTL(SNDRV_SEQ_IOCTL_GET_NAMED_QUEUE),
	IOCTL(SNDRV_SEQ_IOCTL_GET_QUEUE_STATUS),
	IOCTL(SNDRV_SEQ_IOCTL_GET_QUEUE_TEMPO),
	IOCTL(SNDRV_SEQ_IOCTL_SET_QUEUE_TEMPO),
	/* IOCTL(SNDRV_SEQ_IOCTL_GET_QUEUE_OWNER), */
	/* IOCTL(SNDRV_SEQ_IOCTL_SET_QUEUE_OWNER), */
	IOCTL(SNDRV_SEQ_IOCTL_GET_QUEUE_TIMER),
	IOCTL(SNDRV_SEQ_IOCTL_SET_QUEUE_TIMER),
	/* IOCTL(SNDRV_SEQ_IOCTL_GET_QUEUE_SYNC), */
	/* IOCTL(SNDRV_SEQ_IOCTL_SET_QUEUE_SYNC), */
	IOCTL(SNDRV_SEQ_IOCTL_GET_QUEUE_CLIENT),
	IOCTL(SNDRV_SEQ_IOCTL_SET_QUEUE_CLIENT),
	IOCTL(SNDRV_SEQ_IOCTL_GET_CLIENT_POOL),
	IOCTL(SNDRV_SEQ_IOCTL_SET_CLIENT_POOL),
	IOCTL(SNDRV_SEQ_IOCTL_REMOVE_EVENTS),
	IOCTL(SNDRV_SEQ_IOCTL_QUERY_SUBS),
	IOCTL(SNDRV_SEQ_IOCTL_GET_SUBSCRIPTION),
	IOCTL(SNDRV_SEQ_IOCTL_QUERY_NEXT_CLIENT),
	IOCTL(SNDRV_SEQ_IOCTL_QUERY_NEXT_PORT),
	IOCTL(SNDRV_DM_FM_IOCTL_INFO),
	IOCTL(SNDRV_DM_FM_IOCTL_RESET),
	IOCTL(SNDRV_DM_FM_IOCTL_PLAY_NOTE),
	IOCTL(SNDRV_DM_FM_IOCTL_SET_VOICE),
	IOCTL(SNDRV_DM_FM_IOCTL_SET_PARAMS),
	IOCTL(SNDRV_DM_FM_IOCTL_SET_MODE),
	IOCTL(SNDRV_DM_FM_IOCTL_SET_CONNECTION),
	IOCTL(SNDRV_DM_FM_IOCTL_CLEAR_PATCHES),
	IOCTL(SNDRV_HWDEP_IOCTL_PVERSION),
	IOCTL(SNDRV_HWDEP_IOCTL_INFO),
	IOCTL(SNDRV_HWDEP_IOCTL_DSP_STATUS),
	IOCTL(SNDRV_HWDEP_IOCTL_DSP_LOAD),
	IOCTL(SNDRV_PCM_IOCTL_PVERSION),
	IOCTL(SNDRV_PCM_IOCTL_INFO),
	IOCTL(SNDRV_PCM_IOCTL_TSTAMP),
	IOCTL(SNDRV_PCM_IOCTL_TTSTAMP),
	IOCTL(SNDRV_PCM_IOCTL_HW_REFINE),
	IOCTL(SNDRV_PCM_IOCTL_HW_PARAMS),
	IOCTL(SNDRV_PCM_IOCTL_HW_FREE),
	IOCTL(SNDRV_PCM_IOCTL_SW_PARAMS),
	IOCTL(SNDRV_PCM_IOCTL_STATUS),
	IOCTL(SNDRV_PCM_IOCTL_DELAY),
	IOCTL(SNDRV_PCM_IOCTL_HWSYNC),
	IOCTL(SNDRV_PCM_IOCTL_SYNC_PTR),
	IOCTL(SNDRV_PCM_IOCTL_CHANNEL_INFO),
	IOCTL(SNDRV_PCM_IOCTL_PREPARE),
	IOCTL(SNDRV_PCM_IOCTL_RESET),
	IOCTL(SNDRV_PCM_IOCTL_START),
	IOCTL(SNDRV_PCM_IOCTL_DROP),
	IOCTL(SNDRV_PCM_IOCTL_DRAIN),
	IOCTL(SNDRV_PCM_IOCTL_PAUSE),
	IOCTL(SNDRV_PCM_IOCTL_REWIND),
	IOCTL(SNDRV_PCM_IOCTL_RESUME),
	IOCTL(SNDRV_PCM_IOCTL_XRUN),
	IOCTL(SNDRV_PCM_IOCTL_FORWARD),
	IOCTL(SNDRV_PCM_IOCTL_WRITEI_FRAMES),
	IOCTL(SNDRV_PCM_IOCTL_READI_FRAMES),
	IOCTL(SNDRV_PCM_IOCTL_WRITEN_FRAMES),
	IOCTL(SNDRV_PCM_IOCTL_READN_FRAMES),
	IOCTL(SNDRV_PCM_IOCTL_LINK),
	IOCTL(SNDRV_PCM_IOCTL_UNLINK),
	IOCTL(SNDRV_RAWMIDI_IOCTL_PVERSION),
	IOCTL(SNDRV_RAWMIDI_IOCTL_INFO),
	IOCTL(SNDRV_RAWMIDI_IOCTL_PARAMS),
	IOCTL(SNDRV_RAWMIDI_IOCTL_STATUS),
	IOCTL(SNDRV_RAWMIDI_IOCTL_DROP),
	IOCTL(SNDRV_RAWMIDI_IOCTL_DRAIN),
	IOCTL(SNDRV_UMP_IOCTL_ENDPOINT_INFO),
	IOCTL(SNDRV_UMP_IOCTL_BLOCK_INFO),
	IOCTL(SNDRV_TIMER_IOCTL_PVERSION),
	IOCTL(SNDRV_TIMER_IOCTL_NEXT_DEVICE),
	IOCTL(SNDRV_TIMER_IOCTL_TREAD),
	IOCTL(SNDRV_TIMER_IOCTL_GINFO),
	IOCTL(SNDRV_TIMER_IOCTL_GPARAMS),
	IOCTL(SNDRV_TIMER_IOCTL_GSTATUS),
	IOCTL(SNDRV_TIMER_IOCTL_SELECT),
	IOCTL(SNDRV_TIMER_IOCTL_INFO),
	IOCTL(SNDRV_TIMER_IOCTL_PARAMS),
	IOCTL(SNDRV_TIMER_IOCTL_STATUS),
	IOCTL(SNDRV_TIMER_IOCTL_START),
	IOCTL(SNDRV_TIMER_IOCTL_STOP),
	IOCTL(SNDRV_TIMER_IOCTL_CONTINUE),
	IOCTL(SNDRV_TIMER_IOCTL_PAUSE),
	IOCTL(SNDRV_CTL_IOCTL_PVERSION),
	IOCTL(SNDRV_CTL_IOCTL_CARD_INFO),
	IOCTL(SNDRV_CTL_IOCTL_ELEM_LIST),
	IOCTL(SNDRV_CTL_IOCTL_ELEM_INFO),
	IOCTL(SNDRV_CTL_IOCTL_ELEM_READ),
	IOCTL(SNDRV_CTL_IOCTL_ELEM_WRITE),
	IOCTL(SNDRV_CTL_IOCTL_ELEM_LOCK),
	IOCTL(SNDRV_CTL_IOCTL_ELEM_UNLOCK),
	IOCTL(SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS),
	IOCTL(SNDRV_CTL_IOCTL_ELEM_ADD),
	IOCTL(SNDRV_CTL_IOCTL_ELEM_REPLACE),
	IOCTL(SNDRV_CTL_IOCTL_ELEM_REMOVE),
	IOCTL(SNDRV_CTL_IOCTL_TLV_READ),
	IOCTL(SNDRV_CTL_IOCTL_TLV_WRITE),
	IOCTL(SNDRV_CTL_IOCTL_TLV_COMMAND),
	IOCTL(SNDRV_CTL_IOCTL_HWDEP_NEXT_DEVICE),
	IOCTL(SNDRV_CTL_IOCTL_HWDEP_INFO),
	IOCTL(SNDRV_CTL_IOCTL_PCM_NEXT_DEVICE),
	IOCTL(SNDRV_CTL_IOCTL_PCM_INFO),
	IOCTL(SNDRV_CTL_IOCTL_PCM_PREFER_SUBDEVICE),
	IOCTL(SNDRV_CTL_IOCTL_RAWMIDI_NEXT_DEVICE),
	IOCTL(SNDRV_CTL_IOCTL_RAWMIDI_INFO),
	IOCTL(SNDRV_CTL_IOCTL_RAWMIDI_PREFER_SUBDEVICE),
	IOCTL(SNDRV_CTL_IOCTL_POWER),
	IOCTL(SNDRV_CTL_IOCTL_POWER_STATE),
	IOCTL(HDA_IOCTL_PVERSION),
	IOCTL(HDA_IOCTL_VERB_WRITE),
	IOCTL(HDA_IOCTL_GET_WCAP),
	IOCTL(SNDRV_HDSP_IOCTL_GET_PEAK_RMS),
	IOCTL(SNDRV_HDSP_IOCTL_GET_CONFIG_INFO),
	IOCTL(SNDRV_HDSP_IOCTL_UPLOAD_FIRMWARE),
	IOCTL(SNDRV_HDSP_IOCTL_GET_VERSION),
	IOCTL(SNDRV_HDSP_IOCTL_GET_MIXER),
	IOCTL(SNDRV_HDSP_IOCTL_GET_9632_AEB),
	IOCTL(SNDRV_HDSPM_IOCTL_GET_VERSION),
	IOCTL(SNDRV_HDSPM_IOCTL_GET_MIXER),
	IOCTL(SNDRV_SB_CSP_IOCTL_INFO),
	IOCTL(SNDRV_SB_CSP_IOCTL_LOAD_CODE),
	IOCTL(SNDRV_SB_CSP_IOCTL_UNLOAD_CODE),
	IOCTL(SNDRV_SB_CSP_IOCTL_START),
	IOCTL(SNDRV_SB_CSP_IOCTL_STOP),
	IOCTL(SNDRV_SB_CSP_IOCTL_PAUSE),
	IOCTL(SNDRV_SB_CSP_IOCTL_RESTART),
	IOCTL(SNDRV_EMUX_IOCTL_VERSION),
	IOCTL(SNDRV_EMUX_IOCTL_LOAD_PATCH),
	IOCTL(SNDRV_EMUX_IOCTL_RESET_SAMPLES),
	IOCTL(SNDRV_EMUX_IOCTL_REMOVE_LAST_SAMPLES),
	IOCTL(SNDRV_EMUX_IOCTL_MEM_AVAIL),
	IOCTL(SNDRV_EMUX_IOCTL_MISC_MODE),

	{ .name = "SNDRV_EMU10K1_IOCTL_INFO", .request = _IOC(_IOC_NONE,'H',0x10,0), },
	{ .name = "SNDRV_EMU10K1_IOCTL_CODE_POKE", .request = _IOC(_IOC_NONE,'H',0x11,0), },
	{ .name = "SNDRV_EMU10K1_IOCTL_CODE_PEEK", .request = _IOC(_IOC_NONE,'H',0x12,0), },
	{ .name = "SNDRV_EMU10K1_IOCTL_TRAM_SETUP", .request = _IOC(_IOC_NONE,'H',0x20,0), },
	{ .name = "SNDRV_EMU10K1_IOCTL_TRAM_POKE", .request = _IOC(_IOC_NONE,'H',0x21,0), },
	{ .name = "SNDRV_EMU10K1_IOCTL_TRAM_PEEK", .request = _IOC(_IOC_NONE,'H',0x22,0), },
	{ .name = "SNDRV_EMU10K1_IOCTL_PCM_POKE", .request = _IOC(_IOC_NONE,'H',0x30,0), },
	{ .name = "SNDRV_EMU10K1_IOCTL_PCM_PEEK", .request = _IOC(_IOC_NONE,'H',0x31,0), },
	{ .name = "SNDRV_EMU10K1_IOCTL_PVERSION", .request = _IOC(_IOC_NONE,'H',0x40,0), },
	{ .name = "SNDRV_EMU10K1_IOCTL_STOP", .request = _IOC(_IOC_NONE,'H',0x80,0), },
	{ .name = "SNDRV_EMU10K1_IOCTL_CONTINUE", .request = _IOC(_IOC_NONE,'H',0x81,0), },
	{ .name = "SNDRV_EMU10K1_IOCTL_ZERO_TRAM_COUNTER", .request = _IOC(_IOC_NONE,'H',0x82,0), },
	{ .name = "SNDRV_EMU10K1_IOCTL_SINGLE_STEP", .request = _IOC(_IOC_NONE,'H',0x83,0), },
	{ .name = "SNDRV_EMU10K1_IOCTL_DBG_READ", .request = _IOC(_IOC_NONE,'H',0x84,0), },

#ifdef USE_SNDDRV_COMPRESS_OFFLOAD
	IOCTL(SNDRV_COMPRESS_IOCTL_VERSION),
	IOCTL(SNDRV_COMPRESS_GET_CAPS),
	IOCTL(SNDRV_COMPRESS_GET_CODEC_CAPS),
	IOCTL(SNDRV_COMPRESS_SET_PARAMS),
	IOCTL(SNDRV_COMPRESS_GET_PARAMS),
#ifdef SNDRV_COMPRESS_SET_METADATA
	IOCTL(SNDRV_COMPRESS_SET_METADATA),
#endif
#ifdef SNDRV_COMPRESS_GET_METADATA
	IOCTL(SNDRV_COMPRESS_GET_METADATA),
#endif
	IOCTL(SNDRV_COMPRESS_TSTAMP),
	IOCTL(SNDRV_COMPRESS_AVAIL),
	IOCTL(SNDRV_COMPRESS_PAUSE),
	IOCTL(SNDRV_COMPRESS_RESUME),
	IOCTL(SNDRV_COMPRESS_START),
	IOCTL(SNDRV_COMPRESS_STOP),
	IOCTL(SNDRV_COMPRESS_DRAIN),
#ifdef SNDRV_COMPRESS_NEXT_TRACK
	IOCTL(SNDRV_COMPRESS_NEXT_TRACK),
#endif
#ifdef SNDRV_COMPRESS_PARTIAL_DRAIN
	IOCTL(SNDRV_COMPRESS_PARTIAL_DRAIN),
#endif
#endif /* USE_SNDDRV_COMPRESS_OFFLOAD */
};

static const char *const sound_devs[] = {
	"sound",
	"alsa",
};

static const struct ioctl_group sound_grp = {
	.devtype = DEV_CHAR,
	.devs = sound_devs,
	.devs_cnt = ARRAY_SIZE(sound_devs),
	.sanitise = sound_sanitise,
	.ioctls = sound_ioctls,
	.ioctls_cnt = ARRAY_SIZE(sound_ioctls),
};

REG_IOCTL_GROUP(sound_grp)
