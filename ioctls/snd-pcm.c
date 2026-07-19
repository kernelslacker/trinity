
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

/* pcm */
IOCTL_SIZE_ASSERT(SNDRV_PCM_IOCTL_INFO, struct snd_pcm_info);
IOCTL_SIZE_ASSERT(SNDRV_PCM_IOCTL_HW_REFINE, struct snd_pcm_hw_params);
IOCTL_SIZE_ASSERT(SNDRV_PCM_IOCTL_HW_PARAMS, struct snd_pcm_hw_params);
IOCTL_SIZE_ASSERT(SNDRV_PCM_IOCTL_SW_PARAMS, struct snd_pcm_sw_params);
IOCTL_SIZE_ASSERT(SNDRV_PCM_IOCTL_STATUS, struct snd_pcm_status);
IOCTL_SIZE_ASSERT(SNDRV_PCM_IOCTL_STATUS_EXT, struct snd_pcm_status);
IOCTL_SIZE_ASSERT(SNDRV_PCM_IOCTL_CHANNEL_INFO, struct snd_pcm_channel_info);
IOCTL_SIZE_ASSERT(SNDRV_PCM_IOCTL_SYNC_PTR, struct snd_pcm_sync_ptr);
IOCTL_SIZE_ASSERT(SNDRV_PCM_IOCTL_WRITEI_FRAMES, struct snd_xferi);
IOCTL_SIZE_ASSERT(SNDRV_PCM_IOCTL_READI_FRAMES, struct snd_xferi);
IOCTL_SIZE_ASSERT(SNDRV_PCM_IOCTL_WRITEN_FRAMES, struct snd_xfern);
IOCTL_SIZE_ASSERT(SNDRV_PCM_IOCTL_READN_FRAMES, struct snd_xfern);

static const int snd_pcm_stream_vals[] = {
	SNDRV_PCM_STREAM_PLAYBACK,
	SNDRV_PCM_STREAM_CAPTURE,
};

static void fill_snd_pcm_hw_params(struct snd_pcm_hw_params *p)
{
	unsigned int rate;
	unsigned int channels;
	/* index within intervals[]: param - SNDRV_PCM_HW_PARAM_FIRST_INTERVAL */
	unsigned int rate_idx = SNDRV_PCM_HW_PARAM_RATE - SNDRV_PCM_HW_PARAM_FIRST_INTERVAL;
	unsigned int chan_idx = SNDRV_PCM_HW_PARAM_CHANNELS - SNDRV_PCM_HW_PARAM_FIRST_INTERVAL;

	rate = pcm_rates[rnd_modulo_u32(pcm_rates_count)];
	channels = rnd_modulo_u32(8) + 1;

	p->rmask = ~0U;		/* request all params */
	p->intervals[rate_idx].min = rate;
	p->intervals[rate_idx].max = rate;
	p->intervals[rate_idx].integer = 1;
	p->intervals[chan_idx].min = channels;
	p->intervals[chan_idx].max = channels;
	p->intervals[chan_idx].integer = 1;
	/* leave format mask zero: kernel will open it up */
}

static void snd_pcm_sanitise_info(struct syscallrecord *rec)
{
	struct snd_pcm_info *info = get_writable_struct(sizeof(*info));
	if (info) {
		memset(info, 0, sizeof(*info));
		info->device = rnd_modulo_u32(8);
		info->subdevice = rnd_modulo_u32(8);
		info->stream = RAND_ARRAY(snd_pcm_stream_vals);
		rec->a3 = (unsigned long) info;
	}
}

static void snd_pcm_sanitise_tstamp(struct syscallrecord *rec)
{
	int *mode = get_writable_struct(sizeof(int));
	if (mode) {
		*mode = rnd_modulo_u32(3);
		rec->a3 = (unsigned long) mode;
	}
}

static void snd_pcm_sanitise_hw_params(struct syscallrecord *rec)
{
	struct snd_pcm_hw_params *p = get_writable_struct(sizeof(*p));
	if (p) {
		memset(p, 0, sizeof(*p));
		fill_snd_pcm_hw_params(p);
		rec->a3 = (unsigned long) p;
	}
}

static void snd_pcm_sanitise_sw_params(struct syscallrecord *rec)
{
	struct snd_pcm_sw_params *p = get_writable_struct(sizeof(*p));
	if (p) {
		memset(p, 0, sizeof(*p));
		p->avail_min = rnd_modulo_u32(4096) + 1;
		p->start_threshold = rnd_modulo_u32(8192) + 1;
		p->stop_threshold = rnd_modulo_u32(8192) + 1;
		p->tstamp_mode = rnd_modulo_u32(2);
		p->period_step = 1;
		rec->a3 = (unsigned long) p;
	}
}

static void snd_pcm_sanitise_status(struct syscallrecord *rec)
{
	struct snd_pcm_status *st = get_writable_struct(sizeof(*st));
	if (st) {
		memset(st, 0, sizeof(*st));
		/* STATUS_EXT reads audio_tstamp_data as a request hint
		 * for which timestamp variant to report. */
		if (rec->a2 == SNDRV_PCM_IOCTL_STATUS_EXT)
			st->audio_tstamp_data = rnd_modulo_u32(4);
		rec->a3 = (unsigned long) st;
	}
}

static void snd_pcm_sanitise_delay(struct syscallrecord *rec)
{
	snd_pcm_sframes_t *delay = get_writable_struct(sizeof(*delay));
	if (delay)
		rec->a3 = (unsigned long) delay;
}

static void snd_pcm_sanitise_channel_info(struct syscallrecord *rec)
{
	struct snd_pcm_channel_info *info = get_writable_struct(sizeof(*info));
	if (info) {
		memset(info, 0, sizeof(*info));
		info->channel = rnd_modulo_u32(8);
		rec->a3 = (unsigned long) info;
	}
}

static void snd_pcm_sanitise_sync_ptr(struct syscallrecord *rec)
{
	struct snd_pcm_sync_ptr *sp = get_writable_struct(sizeof(*sp));
	if (sp) {
		memset(sp, 0, sizeof(*sp));
		rec->a3 = (unsigned long) sp;
	}
}

static void snd_pcm_sanitise_xferi(struct syscallrecord *rec)
{
	struct snd_xferi *xfer = get_writable_struct(sizeof(*xfer));
	if (xfer) {
		memset(xfer, 0, sizeof(*xfer));
		unsigned int frames = rnd_modulo_u32(1024) + 1;
		void *buf = get_writable_struct(frames * 8);	/* up to 8 bytes/frame */
		if (buf) {
			xfer->buf = buf;
			xfer->frames = frames;
		} else {
			xfer->buf = NULL;
			xfer->frames = 0;
		}
		rec->a3 = (unsigned long) xfer;
	}
}

static void snd_pcm_sanitise_xfern(struct syscallrecord *rec)
{
	struct snd_xfern *xfer = get_writable_struct(sizeof(*xfer));
	if (xfer) {
		memset(xfer, 0, sizeof(*xfer));
		unsigned int frames = rnd_modulo_u32(1024) + 1;
		unsigned int channels = rnd_modulo_u32(8) + 1;
		void **bufs = get_writable_struct(channels * sizeof(void *));
		unsigned int i;
		if (bufs) {
			xfer->bufs = bufs;
			xfer->frames = frames;
			for (i = 0; i < channels; i++)
				bufs[i] = get_writable_struct(frames * 4);
		} else {
			xfer->bufs = NULL;
			xfer->frames = 0;
		}
		rec->a3 = (unsigned long) xfer;
	}
}

static void snd_pcm_sanitise_link(struct syscallrecord *rec)
{
	int *fd = get_writable_struct(sizeof(int));
	if (fd) {
		*fd = rnd_modulo_u32(1024);
		rec->a3 = (unsigned long) fd;
	}
}

static void snd_pcm_sanitise_pause(struct syscallrecord *rec)
{
	int *push = get_writable_struct(sizeof(int));
	if (push) {
		*push = RAND_BOOL();	/* 1=pause, 0=resume */
		rec->a3 = (unsigned long) push;
	}
}

static void snd_pcm_sanitise_uframes(struct syscallrecord *rec)
{
	snd_pcm_uframes_t *frames = get_writable_struct(sizeof(*frames));
	if (frames) {
		*frames = rnd_modulo_u32(4096) + 1;
		rec->a3 = (unsigned long) frames;
	}
}

void sanitise_snd_pcm(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_PCM_IOCTL_INFO:
		snd_pcm_sanitise_info(rec);
		break;
	case SNDRV_PCM_IOCTL_TSTAMP:
	case SNDRV_PCM_IOCTL_TTSTAMP:
		snd_pcm_sanitise_tstamp(rec);
		break;
	case SNDRV_PCM_IOCTL_HW_REFINE:
	case SNDRV_PCM_IOCTL_HW_PARAMS:
		snd_pcm_sanitise_hw_params(rec);
		break;
	case SNDRV_PCM_IOCTL_SW_PARAMS:
		snd_pcm_sanitise_sw_params(rec);
		break;
	case SNDRV_PCM_IOCTL_STATUS:
	case SNDRV_PCM_IOCTL_STATUS_EXT:
		snd_pcm_sanitise_status(rec);
		break;
	case SNDRV_PCM_IOCTL_DELAY:
		snd_pcm_sanitise_delay(rec);
		break;
	case SNDRV_PCM_IOCTL_CHANNEL_INFO:
		snd_pcm_sanitise_channel_info(rec);
		break;
	case SNDRV_PCM_IOCTL_SYNC_PTR:
		snd_pcm_sanitise_sync_ptr(rec);
		break;
	case SNDRV_PCM_IOCTL_WRITEI_FRAMES:
	case SNDRV_PCM_IOCTL_READI_FRAMES:
		snd_pcm_sanitise_xferi(rec);
		break;
	case SNDRV_PCM_IOCTL_WRITEN_FRAMES:
	case SNDRV_PCM_IOCTL_READN_FRAMES:
		snd_pcm_sanitise_xfern(rec);
		break;
	case SNDRV_PCM_IOCTL_LINK:
		snd_pcm_sanitise_link(rec);
		break;
	case SNDRV_PCM_IOCTL_PAUSE:
		snd_pcm_sanitise_pause(rec);
		break;
	case SNDRV_PCM_IOCTL_REWIND:
	case SNDRV_PCM_IOCTL_FORWARD:
		snd_pcm_sanitise_uframes(rec);
		break;
	default:
		break;
	}
}

int dispatch_snd_pcm(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_PCM_IOCTL_INFO:
	case SNDRV_PCM_IOCTL_TSTAMP:
	case SNDRV_PCM_IOCTL_TTSTAMP:
	case SNDRV_PCM_IOCTL_HW_REFINE:
	case SNDRV_PCM_IOCTL_HW_PARAMS:
	case SNDRV_PCM_IOCTL_SW_PARAMS:
	case SNDRV_PCM_IOCTL_STATUS:
	case SNDRV_PCM_IOCTL_STATUS_EXT:
	case SNDRV_PCM_IOCTL_DELAY:
	case SNDRV_PCM_IOCTL_SYNC_PTR:
	case SNDRV_PCM_IOCTL_CHANNEL_INFO:
	case SNDRV_PCM_IOCTL_WRITEI_FRAMES:
	case SNDRV_PCM_IOCTL_READI_FRAMES:
	case SNDRV_PCM_IOCTL_WRITEN_FRAMES:
	case SNDRV_PCM_IOCTL_READN_FRAMES:
	case SNDRV_PCM_IOCTL_LINK:
	case SNDRV_PCM_IOCTL_PAUSE:
	case SNDRV_PCM_IOCTL_REWIND:
	case SNDRV_PCM_IOCTL_FORWARD:
		sanitise_snd_pcm(rec);
		return 1;
	}
	return 0;
}
