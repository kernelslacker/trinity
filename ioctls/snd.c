
#include <inttypes.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/soundcard.h>
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
#include "rnd.h"
#include "sanitise.h"
#include "snd-internal.h"
#include "utils.h"

/* include/sound/hda_hwdep.h */
struct hda_verb_ioctl {
        __u32 verb;       /* HDA_VERB() */
        __u32 res;        /* response */
};
#define HDA_IOCTL_PVERSION              _IOR('H', 0x10, int)
#define HDA_IOCTL_VERB_WRITE            _IOWR('H', 0x11, struct hda_verb_ioctl)
#define HDA_IOCTL_GET_WCAP              _IOWR('H', 0x12, struct hda_verb_ioctl)

/*
 * Compile-time: every fixed-shape sound ioctl the sanitisers below
 * fill must match the _IOC_SIZE its request encodes.  A failure means
 * the ALSA/OSS UAPI moved and a sanitiser is memset()ing / stamping
 * against a stale struct definition -- fix the sanitiser, do not
 * silence.  Skipped by design: TLV / DSP_LOAD-style flex bodies,
 * scalar int/frames args (TSTAMP, DELAY, LINK, PAUSE, REWIND,
 * FORWARD, DROP, DRAIN, TREAD, SUBSCRIBE_EVENTS, *_NEXT_DEVICE,
 * PREFER_SUBDEVICE, POWER, UMP_NEXT_DEVICE), HDSPM, EMU10K1, SB CSP
 * legacy magic-number ioctls that carry driver-specific or
 * pointer-only args, and OSS DSP/mixer int/pointer-only cmds.
 */
IOCTL_SIZE_ASSERT(HDA_IOCTL_VERB_WRITE, struct hda_verb_ioctl);
IOCTL_SIZE_ASSERT(HDA_IOCTL_GET_WCAP, struct hda_verb_ioctl);

/* hwdep */
IOCTL_SIZE_ASSERT(SNDRV_HWDEP_IOCTL_INFO, struct snd_hwdep_info);
IOCTL_SIZE_ASSERT(SNDRV_HWDEP_IOCTL_DSP_STATUS, struct snd_hwdep_dsp_status);
IOCTL_SIZE_ASSERT(SNDRV_HWDEP_IOCTL_DSP_LOAD, struct snd_hwdep_dsp_image);

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

/* rawmidi */
IOCTL_SIZE_ASSERT(SNDRV_RAWMIDI_IOCTL_INFO, struct snd_rawmidi_info);
IOCTL_SIZE_ASSERT(SNDRV_RAWMIDI_IOCTL_PARAMS, struct snd_rawmidi_params);
IOCTL_SIZE_ASSERT(SNDRV_RAWMIDI_IOCTL_STATUS, struct snd_rawmidi_status);

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

/* seq */
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SYSTEM_INFO, struct snd_seq_system_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_RUNNING_MODE, struct snd_seq_running_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_CLIENT_INFO, struct snd_seq_client_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SET_CLIENT_INFO, struct snd_seq_client_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_QUERY_NEXT_CLIENT, struct snd_seq_client_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_CREATE_PORT, struct snd_seq_port_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_DELETE_PORT, struct snd_seq_port_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_PORT_INFO, struct snd_seq_port_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SET_PORT_INFO, struct snd_seq_port_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_QUERY_NEXT_PORT, struct snd_seq_port_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SUBSCRIBE_PORT, struct snd_seq_port_subscribe);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_UNSUBSCRIBE_PORT, struct snd_seq_port_subscribe);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_SUBSCRIPTION, struct snd_seq_port_subscribe);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_CREATE_QUEUE, struct snd_seq_queue_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_DELETE_QUEUE, struct snd_seq_queue_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_QUEUE_INFO, struct snd_seq_queue_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SET_QUEUE_INFO, struct snd_seq_queue_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_NAMED_QUEUE, struct snd_seq_queue_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_QUEUE_STATUS, struct snd_seq_queue_status);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_QUEUE_TEMPO, struct snd_seq_queue_tempo);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SET_QUEUE_TEMPO, struct snd_seq_queue_tempo);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_QUEUE_TIMER, struct snd_seq_queue_timer);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SET_QUEUE_TIMER, struct snd_seq_queue_timer);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_QUEUE_CLIENT, struct snd_seq_queue_client);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SET_QUEUE_CLIENT, struct snd_seq_queue_client);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_CLIENT_POOL, struct snd_seq_client_pool);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SET_CLIENT_POOL, struct snd_seq_client_pool);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_REMOVE_EVENTS, struct snd_seq_remove_events);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_QUERY_SUBS, struct snd_seq_query_subs);
#ifdef SNDRV_SEQ_IOCTL_GET_CLIENT_UMP_INFO
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_CLIENT_UMP_INFO, struct snd_seq_client_ump_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SET_CLIENT_UMP_INFO, struct snd_seq_client_ump_info);
#endif

/* ump */
IOCTL_SIZE_ASSERT(SNDRV_UMP_IOCTL_ENDPOINT_INFO, struct snd_ump_endpoint_info);
IOCTL_SIZE_ASSERT(SNDRV_UMP_IOCTL_BLOCK_INFO, struct snd_ump_block_info);
#ifdef SNDRV_CTL_IOCTL_UMP_ENDPOINT_INFO
IOCTL_SIZE_ASSERT(SNDRV_CTL_IOCTL_UMP_ENDPOINT_INFO, struct snd_ump_endpoint_info);
#endif
#ifdef SNDRV_CTL_IOCTL_UMP_BLOCK_INFO
IOCTL_SIZE_ASSERT(SNDRV_CTL_IOCTL_UMP_BLOCK_INFO, struct snd_ump_block_info);
#endif

/* compress offload */
#ifdef USE_SNDDRV_COMPRESS_OFFLOAD
IOCTL_SIZE_ASSERT(SNDRV_COMPRESS_GET_CAPS, struct snd_compr_caps);
IOCTL_SIZE_ASSERT(SNDRV_COMPRESS_GET_CODEC_CAPS, struct snd_compr_codec_caps);
IOCTL_SIZE_ASSERT(SNDRV_COMPRESS_SET_PARAMS, struct snd_compr_params);
IOCTL_SIZE_ASSERT(SNDRV_COMPRESS_GET_PARAMS, struct snd_codec);
IOCTL_SIZE_ASSERT(SNDRV_COMPRESS_TSTAMP, struct snd_compr_tstamp);
IOCTL_SIZE_ASSERT(SNDRV_COMPRESS_AVAIL, struct snd_compr_avail);
#endif

/* OSS DSP */
IOCTL_SIZE_ASSERT(SNDCTL_DSP_GETOSPACE, audio_buf_info);
IOCTL_SIZE_ASSERT(SNDCTL_DSP_GETISPACE, audio_buf_info);
IOCTL_SIZE_ASSERT(SNDCTL_DSP_GETIPTR, count_info);
IOCTL_SIZE_ASSERT(SNDCTL_DSP_GETOPTR, count_info);

/* OSS mixer */
IOCTL_SIZE_ASSERT(SOUND_MIXER_INFO, mixer_info);
#ifdef SOUND_MIXER_ACCESS
IOCTL_SIZE_ASSERT(SOUND_MIXER_ACCESS, mixer_record);
#endif
#ifdef SOUND_MIXER_GETLEVELS
IOCTL_SIZE_ASSERT(SOUND_MIXER_GETLEVELS, mixer_vol_table);
IOCTL_SIZE_ASSERT(SOUND_MIXER_SETLEVELS, mixer_vol_table);
#endif

static void sanitise_snd_hwdep(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_HWDEP_IOCTL_INFO: {
		struct snd_hwdep_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			memset(info, 0, sizeof(*info));
			info->device = rnd_modulo_u32(8);
			rec->a3 = (unsigned long) info;
		}
		break;
	}
	case SNDRV_HWDEP_IOCTL_DSP_STATUS: {
		struct snd_hwdep_dsp_status *st = get_writable_struct(sizeof(*st));
		if (st) {
			memset(st, 0, sizeof(*st));
			rec->a3 = (unsigned long) st;
		}
		break;
	}
	case SNDRV_HWDEP_IOCTL_DSP_LOAD: {
		struct snd_hwdep_dsp_image *img = get_writable_struct(sizeof(*img));
		if (img) {
			memset(img, 0, sizeof(*img));
			unsigned long length = rnd_modulo_u32(4096) + 1;
			void *image = get_writable_struct(length);
			img->index = rnd_modulo_u32(8);
			if (image) {
				img->image = image;
				img->length = length;
			} else {
				img->image = NULL;
				img->length = 0;
			}
			rec->a3 = (unsigned long) img;
		}
		break;
	}
	default:
		break;
	}
}

static void sanitise_snd_hda_verb(struct syscallrecord *rec)
{
	struct hda_verb_ioctl *v;
	unsigned int nid, verb, param;

	switch (rec->a2) {
	case HDA_IOCTL_VERB_WRITE:
	case HDA_IOCTL_GET_WCAP:
		v = get_writable_struct(sizeof(*v));
		if (!v)
			break;
		memset(v, 0, sizeof(*v));
		/* nid in the top byte; verb in bits 8-23; param in low byte. */
		nid = rnd_u32() & 0xff;
		verb = rnd_u32() & 0xffff;
		param = rnd_u32() & 0xff;
		v->verb = (nid << 24) | (verb << 8) | param;
		rec->a3 = (unsigned long) v;
		break;
	default:
		break;
	}
}

static const int snd_pcm_stream_vals[] = {
	SNDRV_PCM_STREAM_PLAYBACK,
	SNDRV_PCM_STREAM_CAPTURE,
};

static const int snd_rawmidi_stream_vals[] = {
	SNDRV_RAWMIDI_STREAM_OUTPUT,
	SNDRV_RAWMIDI_STREAM_INPUT,
};

static const int snd_timer_class_vals[] = {
	SNDRV_TIMER_CLASS_NONE,
	SNDRV_TIMER_CLASS_SLAVE,
	SNDRV_TIMER_CLASS_GLOBAL,
	SNDRV_TIMER_CLASS_CARD,
	SNDRV_TIMER_CLASS_PCM,
};

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

	rate = pcm_rates[rnd_modulo_u32(ARRAY_SIZE(pcm_rates))];
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

static void sanitise_snd_pcm(struct syscallrecord *rec)
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

static void sanitise_snd_rawmidi(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_RAWMIDI_IOCTL_INFO: {
		struct snd_rawmidi_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			memset(info, 0, sizeof(*info));
			info->device = rnd_modulo_u32(8);
			info->subdevice = rnd_modulo_u32(8);
			info->stream = RAND_ARRAY(snd_rawmidi_stream_vals);
			rec->a3 = (unsigned long) info;
		}
		break;
	}
	case SNDRV_RAWMIDI_IOCTL_PARAMS: {
		struct snd_rawmidi_params *p = get_writable_struct(sizeof(*p));
		if (p) {
			memset(p, 0, sizeof(*p));
			p->stream = RAND_ARRAY(snd_rawmidi_stream_vals);
			p->buffer_size = (rnd_modulo_u32(16) + 1) * 4096;
			p->avail_min = rnd_modulo_u32(256) + 1;
			rec->a3 = (unsigned long) p;
		}
		break;
	}
	case SNDRV_RAWMIDI_IOCTL_STATUS: {
		struct snd_rawmidi_status *st = get_writable_struct(sizeof(*st));
		if (st) {
			memset(st, 0, sizeof(*st));
			st->stream = RAND_ARRAY(snd_rawmidi_stream_vals);
			rec->a3 = (unsigned long) st;
		}
		break;
	}
	case SNDRV_RAWMIDI_IOCTL_DROP:
	case SNDRV_RAWMIDI_IOCTL_DRAIN: {
		int *stream = get_writable_struct(sizeof(int));
		if (stream) {
			*stream = RAND_ARRAY(snd_rawmidi_stream_vals);
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

static void sanitise_snd_timer(struct syscallrecord *rec)
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

static void fill_snd_seq_addr(struct snd_seq_addr *addr)
{
	addr->client = rnd_modulo_u32(128);
	addr->port = rnd_modulo_u32(256);
}

static void sanitise_snd_seq_system_info(struct syscallrecord *rec)
{
	struct snd_seq_system_info *info = get_writable_struct(sizeof(*info));
	if (info) {
		memset(info, 0, sizeof(*info));
		rec->a3 = (unsigned long) info;
	}
}

static void sanitise_snd_seq_running_mode(struct syscallrecord *rec)
{
	struct snd_seq_running_info *info = get_writable_struct(sizeof(*info));
	if (info) {
		memset(info, 0, sizeof(*info));
		info->client = rnd_modulo_u32(128);
		rec->a3 = (unsigned long) info;
	}
}

static void sanitise_snd_seq_client_info(struct syscallrecord *rec)
{
	struct snd_seq_client_info *ci = get_writable_struct(sizeof(*ci));
	if (ci) {
		memset(ci, 0, sizeof(*ci));
		ci->client = RAND_BOOL() ? -1 : (int)(rnd_modulo_u32(128));
		rec->a3 = (unsigned long) ci;
	}
}

static void sanitise_snd_seq_port_info(struct syscallrecord *rec)
{
	struct snd_seq_port_info *pi = get_writable_struct(sizeof(*pi));
	if (pi) {
		memset(pi, 0, sizeof(*pi));
		fill_snd_seq_addr(&pi->addr);
		if (rec->a2 == SNDRV_SEQ_IOCTL_QUERY_NEXT_PORT)
			pi->addr.port = (unsigned char)(rnd_modulo_u32(256) - 1);
		pi->capability = rnd_u32();
		pi->type = rnd_u32();
		pi->midi_channels = rnd_modulo_u32(16) + 1;
		rec->a3 = (unsigned long) pi;
	}
}

static void sanitise_snd_seq_port_subscribe(struct syscallrecord *rec)
{
	struct snd_seq_port_subscribe *sub = get_writable_struct(sizeof(*sub));
	if (sub) {
		memset(sub, 0, sizeof(*sub));
		fill_snd_seq_addr(&sub->sender);
		fill_snd_seq_addr(&sub->dest);
		rec->a3 = (unsigned long) sub;
	}
}

static void sanitise_snd_seq_queue_info(struct syscallrecord *rec)
{
	struct snd_seq_queue_info *qi = get_writable_struct(sizeof(*qi));
	if (qi) {
		memset(qi, 0, sizeof(*qi));
		qi->queue = rnd_modulo_u32(8);
		qi->owner = rnd_modulo_u32(128);
		rec->a3 = (unsigned long) qi;
	}
}

static void sanitise_snd_seq_queue_status(struct syscallrecord *rec)
{
	struct snd_seq_queue_status *qs = get_writable_struct(sizeof(*qs));
	if (qs) {
		memset(qs, 0, sizeof(*qs));
		qs->queue = rnd_modulo_u32(8);
		rec->a3 = (unsigned long) qs;
	}
}

static void sanitise_snd_seq_queue_tempo(struct syscallrecord *rec)
{
	struct snd_seq_queue_tempo *qt = get_writable_struct(sizeof(*qt));
	if (qt) {
		memset(qt, 0, sizeof(*qt));
		qt->queue = rnd_modulo_u32(8);
		qt->tempo = rnd_modulo_u32(2000000) + 60000;	/* 60ms-2s per beat */
		qt->ppq = rnd_modulo_u32(480) + 24;
		rec->a3 = (unsigned long) qt;
	}
}

static void sanitise_snd_seq_queue_timer(struct syscallrecord *rec)
{
	struct snd_seq_queue_timer *timer = get_writable_struct(sizeof(*timer));
	if (timer) {
		memset(timer, 0, sizeof(*timer));
		timer->queue = rnd_modulo_u32(8);
		timer->type = rnd_modulo_u32(3);
		fill_snd_timer_id(&timer->u.alsa.id);
		timer->u.alsa.resolution = rnd_modulo_u32(480) + 24;
		rec->a3 = (unsigned long) timer;
	}
}

static void sanitise_snd_seq_queue_client(struct syscallrecord *rec)
{
	struct snd_seq_queue_client *qc = get_writable_struct(sizeof(*qc));
	if (qc) {
		memset(qc, 0, sizeof(*qc));
		qc->queue = rnd_modulo_u32(8);
		qc->client = rnd_modulo_u32(128);
		qc->used = RAND_BOOL();
		rec->a3 = (unsigned long) qc;
	}
}

static void sanitise_snd_seq_client_pool(struct syscallrecord *rec)
{
	struct snd_seq_client_pool *cp = get_writable_struct(sizeof(*cp));
	if (cp) {
		memset(cp, 0, sizeof(*cp));
		cp->client = rnd_modulo_u32(128);
		cp->output_pool = rnd_modulo_u32(1024) + 64;
		cp->input_pool = rnd_modulo_u32(512) + 32;
		cp->output_room = rnd_modulo_u32(64) + 1;
		rec->a3 = (unsigned long) cp;
	}
}

static void sanitise_snd_seq_remove_events(struct syscallrecord *rec)
{
	struct snd_seq_remove_events *re = get_writable_struct(sizeof(*re));
	if (re) {
		memset(re, 0, sizeof(*re));
		re->remove_mode = rnd_u32() & 0x3ff;
		rec->a3 = (unsigned long) re;
	}
}

static void sanitise_snd_seq_query_subs(struct syscallrecord *rec)
{
	struct snd_seq_query_subs *qs = get_writable_struct(sizeof(*qs));
	if (qs) {
		memset(qs, 0, sizeof(*qs));
		fill_snd_seq_addr(&qs->root);
		qs->type = rnd_u32() & 1;
		qs->index = rnd_modulo_u32(64);
		rec->a3 = (unsigned long) qs;
	}
}

#ifdef SNDRV_SEQ_IOCTL_GET_CLIENT_UMP_INFO
static void sanitise_snd_seq_client_ump_info(struct syscallrecord *rec)
{
	struct snd_seq_client_ump_info *ui = get_writable_struct(sizeof(*ui));
	if (ui) {
		memset(ui, 0, sizeof(*ui));
		ui->client = RAND_BOOL() ? -1 : (int)(rnd_modulo_u32(128));
		ui->type = rnd_u32() & 1;	/* ENDPOINT or BLOCK */
		rec->a3 = (unsigned long) ui;
	}
}
#endif

static void sanitise_snd_seq(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_SEQ_IOCTL_SYSTEM_INFO:
		sanitise_snd_seq_system_info(rec);
		break;
	case SNDRV_SEQ_IOCTL_RUNNING_MODE:
		sanitise_snd_seq_running_mode(rec);
		break;
	case SNDRV_SEQ_IOCTL_GET_CLIENT_INFO:
	case SNDRV_SEQ_IOCTL_SET_CLIENT_INFO:
	case SNDRV_SEQ_IOCTL_QUERY_NEXT_CLIENT:
		sanitise_snd_seq_client_info(rec);
		break;
	case SNDRV_SEQ_IOCTL_CREATE_PORT:
	case SNDRV_SEQ_IOCTL_DELETE_PORT:
	case SNDRV_SEQ_IOCTL_GET_PORT_INFO:
	case SNDRV_SEQ_IOCTL_SET_PORT_INFO:
	case SNDRV_SEQ_IOCTL_QUERY_NEXT_PORT:
		sanitise_snd_seq_port_info(rec);
		break;
	case SNDRV_SEQ_IOCTL_SUBSCRIBE_PORT:
	case SNDRV_SEQ_IOCTL_UNSUBSCRIBE_PORT:
	case SNDRV_SEQ_IOCTL_GET_SUBSCRIPTION:
		sanitise_snd_seq_port_subscribe(rec);
		break;
	case SNDRV_SEQ_IOCTL_CREATE_QUEUE:
	case SNDRV_SEQ_IOCTL_DELETE_QUEUE:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_INFO:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_INFO:
	case SNDRV_SEQ_IOCTL_GET_NAMED_QUEUE:
		sanitise_snd_seq_queue_info(rec);
		break;
	case SNDRV_SEQ_IOCTL_GET_QUEUE_STATUS:
		sanitise_snd_seq_queue_status(rec);
		break;
	case SNDRV_SEQ_IOCTL_GET_QUEUE_TEMPO:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_TEMPO:
		sanitise_snd_seq_queue_tempo(rec);
		break;
	case SNDRV_SEQ_IOCTL_GET_QUEUE_TIMER:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_TIMER:
		sanitise_snd_seq_queue_timer(rec);
		break;
	case SNDRV_SEQ_IOCTL_GET_QUEUE_CLIENT:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_CLIENT:
		sanitise_snd_seq_queue_client(rec);
		break;
	case SNDRV_SEQ_IOCTL_GET_CLIENT_POOL:
	case SNDRV_SEQ_IOCTL_SET_CLIENT_POOL:
		sanitise_snd_seq_client_pool(rec);
		break;
	case SNDRV_SEQ_IOCTL_REMOVE_EVENTS:
		sanitise_snd_seq_remove_events(rec);
		break;
	case SNDRV_SEQ_IOCTL_QUERY_SUBS:
		sanitise_snd_seq_query_subs(rec);
		break;
#ifdef SNDRV_SEQ_IOCTL_GET_CLIENT_UMP_INFO
	case SNDRV_SEQ_IOCTL_GET_CLIENT_UMP_INFO:
	case SNDRV_SEQ_IOCTL_SET_CLIENT_UMP_INFO:
		sanitise_snd_seq_client_ump_info(rec);
		break;
#endif
	default:
		break;
	}
}

static void sanitise_snd_ump(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_UMP_IOCTL_ENDPOINT_INFO:
#ifdef SNDRV_CTL_IOCTL_UMP_ENDPOINT_INFO
	case SNDRV_CTL_IOCTL_UMP_ENDPOINT_INFO:
#endif
	{
		struct snd_ump_endpoint_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			memset(info, 0, sizeof(*info));
			info->card = rnd_modulo_u32(8);
			info->device = rnd_modulo_u32(8);
			rec->a3 = (unsigned long) info;
		}
		break;
	}
	case SNDRV_UMP_IOCTL_BLOCK_INFO:
#ifdef SNDRV_CTL_IOCTL_UMP_BLOCK_INFO
	case SNDRV_CTL_IOCTL_UMP_BLOCK_INFO:
#endif
	{
		struct snd_ump_block_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			memset(info, 0, sizeof(*info));
			info->card = rnd_modulo_u32(8);
			info->device = rnd_modulo_u32(8);
			info->block_id = rnd_modulo_u32(SNDRV_UMP_MAX_BLOCKS);
			rec->a3 = (unsigned long) info;
		}
		break;
	}
#ifdef SNDRV_CTL_IOCTL_UMP_NEXT_DEVICE
	case SNDRV_CTL_IOCTL_UMP_NEXT_DEVICE: {
		int *dev = get_writable_struct(sizeof(int));
		if (dev) {
			*dev = (int)(rnd_modulo_u32(8)) - 1;
			rec->a3 = (unsigned long) dev;
		}
		break;
	}
#endif
	default:
		break;
	}
}

static void sanitise_snd_hdspm(struct syscallrecord *rec)
{
	/* All HDSPM ioctls just take a pointer to a driver-specific struct.
	 * The kernel populates them as _IOR. Allocate enough space for the
	 * largest member (~8KB) and let the driver fail validation cleanly
	 * if it doesn't recognise the device. */
	void *buf = get_writable_struct(8192);
	if (buf)
		rec->a3 = (unsigned long) buf;
}

static const int copr_codes[] = {
	0, 1, 2, 3, 4, 0xff, 0x100,
};

static void sanitise_oss_copr(struct syscallrecord *rec)
{
	/* OSS coprocessor ioctls are legacy SoundBlaster DSP poke/peek.
	 * All take pointers to small structs (copr_buffer ~4KB,
	 * copr_debug_buf ~8 bytes, copr_msg ~4KB). Allocate generously and
	 * leave fields zero — the driver will validate ranges. */
	void *buf = get_writable_struct(4096);
	if (buf) {
		/* First two ints in copr_buffer/copr_debug_buf are command
		 * and parm — drive them with bounded values. */
		int *p = buf;
		p[0] = copr_codes[rnd_modulo_u32(ARRAY_SIZE(copr_codes))];
		p[1] = rnd_modulo_u32(1024);
		rec->a3 = (unsigned long) buf;
	}
}

static const int afmt_vals[] = {
	AFMT_MU_LAW, AFMT_A_LAW, AFMT_IMA_ADPCM, AFMT_U8,
	AFMT_S16_LE, AFMT_S16_BE, AFMT_S8, AFMT_U16_LE,
	AFMT_U16_BE, AFMT_MPEG, AFMT_AC3, AFMT_QUERY,
};

static void sanitise_oss_dsp(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDCTL_DSP_SPEED: {
		int *rate = get_writable_struct(sizeof(int));
		if (rate) {
			*rate = pcm_rates[rnd_modulo_u32(ARRAY_SIZE(pcm_rates))];
			rec->a3 = (unsigned long) rate;
		}
		break;
	}
	case SNDCTL_DSP_STEREO: {
		int *stereo = get_writable_struct(sizeof(int));
		if (stereo) {
			*stereo = rnd_u32() & 1;
			rec->a3 = (unsigned long) stereo;
		}
		break;
	}
	case SNDCTL_DSP_CHANNELS: {
		int *ch = get_writable_struct(sizeof(int));
		if (ch) {
			*ch = rnd_modulo_u32(8) + 1;
			rec->a3 = (unsigned long) ch;
		}
		break;
	}
	case SNDCTL_DSP_SETFMT: {
		int *fmt = get_writable_struct(sizeof(int));
		if (fmt) {
			*fmt = afmt_vals[rnd_modulo_u32(ARRAY_SIZE(afmt_vals))];
			rec->a3 = (unsigned long) fmt;
		}
		break;
	}
	case SNDCTL_DSP_SETFRAGMENT: {
		/* low 16 bits: log2(fragment size), 4-15; high 16 bits: max fragments */
		int *frag = get_writable_struct(sizeof(int));
		if (frag) {
			int fsz = rnd_modulo_u32(12) + 4;
			int nf = RAND_BOOL() ? 0 : (rnd_modulo_u32(15) + 2);
			*frag = fsz | (nf << 16);
			rec->a3 = (unsigned long) frag;
		}
		break;
	}
	case SNDCTL_DSP_SUBDIVIDE: {
		int *sub = get_writable_struct(sizeof(int));
		if (sub) {
			/* legal values are 1, 2, 4 */
			static const int subdivs[] = { 1, 2, 4 };
			*sub = subdivs[rnd_modulo_u32(3)];
			rec->a3 = (unsigned long) sub;
		}
		break;
	}
	case SNDCTL_DSP_SETTRIGGER: {
		int *trig = get_writable_struct(sizeof(int));
		if (trig) {
			*trig = rnd_u32() & (PCM_ENABLE_INPUT | PCM_ENABLE_OUTPUT);
			rec->a3 = (unsigned long) trig;
		}
		break;
	}
	case SNDCTL_DSP_GETOSPACE:
	case SNDCTL_DSP_GETISPACE: {
		audio_buf_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			memset(info, 0, sizeof(*info));
			rec->a3 = (unsigned long) info;
		}
		break;
	}
	case SNDCTL_DSP_GETIPTR:
	case SNDCTL_DSP_GETOPTR: {
		count_info *ci = get_writable_struct(sizeof(*ci));
		if (ci) {
			memset(ci, 0, sizeof(*ci));
			rec->a3 = (unsigned long) ci;
		}
		break;
	}
	default: {
		/* GETBLKSIZE, GETFMTS, GETCAPS, GETTRIGGER, GETODELAY: writable int */
		int *val = get_writable_struct(sizeof(int));
		if (val)
			rec->a3 = (unsigned long) val;
		break;
	}
	}
}

static void sanitise_oss_mixer(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SOUND_MIXER_INFO: {
		mixer_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			memset(info, 0, sizeof(*info));
			rec->a3 = (unsigned long) info;
		}
		break;
	}
#ifdef SOUND_MIXER_ACCESS
	case SOUND_MIXER_ACCESS: {
		mixer_record *mr = get_writable_struct(sizeof(*mr));
		if (mr) {
			memset(mr, 0, sizeof(*mr));
			rec->a3 = (unsigned long) mr;
		}
		break;
	}
#endif
#ifdef SOUND_MIXER_GETLEVELS
	case SOUND_MIXER_GETLEVELS:
	case SOUND_MIXER_SETLEVELS: {
		mixer_vol_table *vt = get_writable_struct(sizeof(*vt));
		if (vt) {
			memset(vt, 0, sizeof(*vt));
			vt->num = rnd_modulo_u32(SOUND_MIXER_NRDEVICES);
			vt->levels[0] = rnd_modulo_u32(101);
			vt->levels[1] = rnd_modulo_u32(101);
			rec->a3 = (unsigned long) vt;
		}
		break;
	}
#endif
	default: {
		/* MIXER_WRITE: packed stereo volume — low byte left, high byte right (0-100 each).
		 * MIXER_READ and bitmask reads (DEVMASK, RECMASK, RECSRC, etc.) just need
		 * a writable int. */
		int *val = get_writable_struct(sizeof(int));
		if (val) {
			if (_IOC_DIR(rec->a2) & _IOC_WRITE)
				*val = (rnd_modulo_u32(101)) | ((rnd_modulo_u32(101)) << 8);
			rec->a3 = (unsigned long) val;
		}
		break;
	}
	}
}

#ifdef USE_SNDDRV_COMPRESS_OFFLOAD
static const __u32 compr_codecs[] = {
	SND_AUDIOCODEC_PCM,
	SND_AUDIOCODEC_MP3,
	SND_AUDIOCODEC_AMR,
	SND_AUDIOCODEC_AMRWB,
	SND_AUDIOCODEC_AAC,
	SND_AUDIOCODEC_WMA,
	SND_AUDIOCODEC_VORBIS,
	SND_AUDIOCODEC_FLAC,
	SND_AUDIOCODEC_IEC61937,
};

static void fill_snd_codec(struct snd_codec *c)
{
	c->id = compr_codecs[rnd_modulo_u32(ARRAY_SIZE(compr_codecs))];
	c->ch_in = rnd_modulo_u32(8) + 1;
	c->ch_out = rnd_modulo_u32(8) + 1;
	c->sample_rate = pcm_rates[rnd_modulo_u32(ARRAY_SIZE(pcm_rates))];
	c->bit_rate = (rnd_modulo_u32(320) + 32) * 1000;
	/* leave profile/level/format/options zero — kernel validates per codec */
}

static void sanitise_snd_compress(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_COMPRESS_GET_CAPS: {
		struct snd_compr_caps *caps = get_writable_struct(sizeof(*caps));
		if (caps) {
			memset(caps, 0, sizeof(*caps));
			rec->a3 = (unsigned long) caps;
		}
		break;
	}
	case SNDRV_COMPRESS_GET_CODEC_CAPS: {
		struct snd_compr_codec_caps *cc = get_writable_struct(sizeof(*cc));
		if (cc) {
			memset(cc, 0, sizeof(*cc));
			cc->codec = compr_codecs[rnd_modulo_u32(ARRAY_SIZE(compr_codecs))];
			rec->a3 = (unsigned long) cc;
		}
		break;
	}
	case SNDRV_COMPRESS_SET_PARAMS: {
		struct snd_compr_params *p = get_writable_struct(sizeof(*p));
		if (p) {
			memset(p, 0, sizeof(*p));
			/* fragment_size: power of two between 4 KB and 64 KB */
			p->buffer.fragment_size = 1U << (rnd_modulo_u32(5) + 12);
			p->buffer.fragments = rnd_modulo_u32(8) + 2;
			fill_snd_codec(&p->codec);
			p->no_wake_mode = RAND_BOOL();
			rec->a3 = (unsigned long) p;
		}
		break;
	}
	case SNDRV_COMPRESS_GET_PARAMS: {
		struct snd_codec *c = get_writable_struct(sizeof(*c));
		if (c) {
			memset(c, 0, sizeof(*c));
			rec->a3 = (unsigned long) c;
		}
		break;
	}
	case SNDRV_COMPRESS_TSTAMP: {
		struct snd_compr_tstamp *t = get_writable_struct(sizeof(*t));
		if (t) {
			memset(t, 0, sizeof(*t));
			rec->a3 = (unsigned long) t;
		}
		break;
	}
	case SNDRV_COMPRESS_AVAIL: {
		struct snd_compr_avail *a = get_writable_struct(sizeof(*a));
		if (a) {
			memset(a, 0, sizeof(*a));
			rec->a3 = (unsigned long) a;
		}
		break;
	}
	default:
		break;
	}
}
#endif /* USE_SNDDRV_COMPRESS_OFFLOAD */

/* snd-hwdep */
static int dispatch_snd_hwdep(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_HWDEP_IOCTL_INFO:
	case SNDRV_HWDEP_IOCTL_DSP_STATUS:
	case SNDRV_HWDEP_IOCTL_DSP_LOAD:
		sanitise_snd_hwdep(rec);
		return 1;
	}
	return 0;
}

/* snd-hda-codec hwdep verb interface */
static int dispatch_snd_hda_verb(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case HDA_IOCTL_VERB_WRITE:
	case HDA_IOCTL_GET_WCAP:
		sanitise_snd_hda_verb(rec);
		return 1;
	}
	return 0;
}

/* snd-control */
/* snd-pcm */
static int dispatch_snd_pcm(struct syscallrecord *rec)
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

/* snd-rawmidi */
static int dispatch_snd_rawmidi(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_RAWMIDI_IOCTL_INFO:
	case SNDRV_RAWMIDI_IOCTL_PARAMS:
	case SNDRV_RAWMIDI_IOCTL_STATUS:
	case SNDRV_RAWMIDI_IOCTL_DROP:
	case SNDRV_RAWMIDI_IOCTL_DRAIN:
		sanitise_snd_rawmidi(rec);
		return 1;
	}
	return 0;
}

/* snd-ump (also reachable via /dev/snd/controlC* with the SNDRV_CTL_* aliases) */
static int dispatch_snd_ump(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_UMP_IOCTL_ENDPOINT_INFO:
	case SNDRV_UMP_IOCTL_BLOCK_INFO:
#ifdef SNDRV_CTL_IOCTL_UMP_NEXT_DEVICE
	case SNDRV_CTL_IOCTL_UMP_NEXT_DEVICE:
	case SNDRV_CTL_IOCTL_UMP_ENDPOINT_INFO:
	case SNDRV_CTL_IOCTL_UMP_BLOCK_INFO:
#endif
		sanitise_snd_ump(rec);
		return 1;
	}
	return 0;
}

/* snd-timer */
static int dispatch_snd_timer(struct syscallrecord *rec)
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

/* OSS PCM (/dev/dsp, type 'P') */
static int dispatch_oss_dsp(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDCTL_DSP_SPEED:
	case SNDCTL_DSP_STEREO:
	case SNDCTL_DSP_GETBLKSIZE:
	case SNDCTL_DSP_SETFMT:
	case SNDCTL_DSP_CHANNELS:
	case SNDCTL_DSP_SUBDIVIDE:
	case SNDCTL_DSP_SETFRAGMENT:
	case SNDCTL_DSP_GETFMTS:
	case SNDCTL_DSP_GETOSPACE:
	case SNDCTL_DSP_GETISPACE:
	case SNDCTL_DSP_GETCAPS:
	case SNDCTL_DSP_GETTRIGGER:
	case SNDCTL_DSP_SETTRIGGER:
	case SNDCTL_DSP_GETIPTR:
	case SNDCTL_DSP_GETOPTR:
	case SNDCTL_DSP_GETODELAY:
#ifdef SNDCTL_DSP_GETCHANNELMASK
	case SNDCTL_DSP_GETCHANNELMASK:
#endif
#ifdef SNDCTL_DSP_BIND_CHANNEL
	case SNDCTL_DSP_BIND_CHANNEL:
#endif
#ifdef SNDCTL_DSP_GETSPDIF
	case SNDCTL_DSP_GETSPDIF:
#endif
#ifdef SNDCTL_DSP_SETSPDIF
	case SNDCTL_DSP_SETSPDIF:
#endif
#ifdef SNDCTL_DSP_PROFILE
	case SNDCTL_DSP_PROFILE:
#endif
		sanitise_oss_dsp(rec);
		return 1;
	}
	return 0;
}

/* OSS mixer (/dev/mixer, type 'M') */
static int dispatch_oss_mixer(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SOUND_MIXER_READ_VOLUME:
	case SOUND_MIXER_READ_BASS:
	case SOUND_MIXER_READ_TREBLE:
	case SOUND_MIXER_READ_SYNTH:
	case SOUND_MIXER_READ_PCM:
	case SOUND_MIXER_READ_SPEAKER:
	case SOUND_MIXER_READ_LINE:
	case SOUND_MIXER_READ_MIC:
	case SOUND_MIXER_READ_CD:
	case SOUND_MIXER_READ_IMIX:
	case SOUND_MIXER_READ_ALTPCM:
	case SOUND_MIXER_READ_RECLEV:
	case SOUND_MIXER_READ_IGAIN:
	case SOUND_MIXER_READ_OGAIN:
	case SOUND_MIXER_READ_LINE1:
	case SOUND_MIXER_READ_LINE2:
	case SOUND_MIXER_READ_LINE3:
	case SOUND_MIXER_READ_RECSRC:
	case SOUND_MIXER_READ_DEVMASK:
	case SOUND_MIXER_READ_RECMASK:
	case SOUND_MIXER_READ_STEREODEVS:
	case SOUND_MIXER_READ_CAPS:
	case SOUND_MIXER_WRITE_VOLUME:
	case SOUND_MIXER_WRITE_BASS:
	case SOUND_MIXER_WRITE_TREBLE:
	case SOUND_MIXER_WRITE_SYNTH:
	case SOUND_MIXER_WRITE_PCM:
	case SOUND_MIXER_WRITE_SPEAKER:
	case SOUND_MIXER_WRITE_LINE:
	case SOUND_MIXER_WRITE_MIC:
	case SOUND_MIXER_WRITE_CD:
	case SOUND_MIXER_WRITE_IMIX:
	case SOUND_MIXER_WRITE_ALTPCM:
	case SOUND_MIXER_WRITE_RECLEV:
	case SOUND_MIXER_WRITE_IGAIN:
	case SOUND_MIXER_WRITE_OGAIN:
	case SOUND_MIXER_WRITE_LINE1:
	case SOUND_MIXER_WRITE_LINE2:
	case SOUND_MIXER_WRITE_LINE3:
	case SOUND_MIXER_WRITE_RECSRC:
	case SOUND_MIXER_INFO:
#ifdef SOUND_MIXER_AGC
	case SOUND_MIXER_AGC:
#endif
#ifdef SOUND_MIXER_3DSE
	case SOUND_MIXER_3DSE:
#endif
#ifdef SOUND_MIXER_ACCESS
	case SOUND_MIXER_ACCESS:
#endif
#ifdef SOUND_MIXER_GETLEVELS
	case SOUND_MIXER_GETLEVELS:
	case SOUND_MIXER_SETLEVELS:
#endif
#ifdef OSS_GETVERSION
	case OSS_GETVERSION:
#endif
		sanitise_oss_mixer(rec);
		return 1;
	}
	return 0;
}

/* snd-hdspm (RME HDSPe MADI/AES/RayDAT/AIO) — newer ioctls only */
static int dispatch_snd_hdspm(struct syscallrecord *rec)
{
	switch (rec->a2) {
#ifdef SNDRV_HDSPM_IOCTL_GET_PEAK_RMS
	case SNDRV_HDSPM_IOCTL_GET_PEAK_RMS:
#endif
#ifdef SNDRV_HDSPM_IOCTL_GET_CONFIG
	case SNDRV_HDSPM_IOCTL_GET_CONFIG:
#endif
#ifdef SNDRV_HDSPM_IOCTL_GET_LTC
	case SNDRV_HDSPM_IOCTL_GET_LTC:
#endif
#ifdef SNDRV_HDSPM_IOCTL_GET_STATUS
	case SNDRV_HDSPM_IOCTL_GET_STATUS:
#endif
#if defined(SNDRV_HDSPM_IOCTL_GET_PEAK_RMS) || \
    defined(SNDRV_HDSPM_IOCTL_GET_CONFIG)  || \
    defined(SNDRV_HDSPM_IOCTL_GET_LTC)     || \
    defined(SNDRV_HDSPM_IOCTL_GET_STATUS)
		sanitise_snd_hdspm(rec);
		return 1;
#endif
	}
	return 0;
}

#ifdef SNDCTL_COPR_LOAD
/* OSS DSP coprocessor (legacy SoundBlaster) */
static int dispatch_oss_copr(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDCTL_COPR_LOAD:
	case SNDCTL_COPR_RDATA:
	case SNDCTL_COPR_RCODE:
	case SNDCTL_COPR_WDATA:
	case SNDCTL_COPR_WCODE:
	case SNDCTL_COPR_RUN:
	case SNDCTL_COPR_HALT:
	case SNDCTL_COPR_SENDMSG:
	case SNDCTL_COPR_RCVMSG:
		sanitise_oss_copr(rec);
		return 1;
	}
	return 0;
}
#endif

#ifdef USE_SNDDRV_COMPRESS_OFFLOAD
/* snd-compress (compressed audio offload) */
static int dispatch_snd_compress(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_COMPRESS_GET_CAPS:
	case SNDRV_COMPRESS_GET_CODEC_CAPS:
	case SNDRV_COMPRESS_SET_PARAMS:
	case SNDRV_COMPRESS_GET_PARAMS:
	case SNDRV_COMPRESS_TSTAMP:
	case SNDRV_COMPRESS_AVAIL:
		sanitise_snd_compress(rec);
		return 1;
	}
	return 0;
}
#endif

/* snd-seq */
static int dispatch_snd_seq(struct syscallrecord *rec)
{
	switch (rec->a2) {
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
#ifdef SNDRV_SEQ_IOCTL_GET_CLIENT_UMP_INFO
	case SNDRV_SEQ_IOCTL_GET_CLIENT_UMP_INFO:
	case SNDRV_SEQ_IOCTL_SET_CLIENT_UMP_INFO:
#endif
		sanitise_snd_seq(rec);
		return 1;
	}
	return 0;
}

static void sound_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	if (dispatch_snd_hwdep(rec))    return;
	if (dispatch_snd_hda_verb(rec)) return;
	if (dispatch_snd_ctl(rec))      return;
	if (dispatch_snd_pcm(rec))      return;
	if (dispatch_snd_rawmidi(rec))  return;
	if (dispatch_snd_ump(rec))      return;
	if (dispatch_snd_timer(rec))    return;
	if (dispatch_oss_dsp(rec))      return;
	if (dispatch_oss_mixer(rec))    return;
	if (dispatch_snd_hdspm(rec))    return;
#ifdef SNDCTL_COPR_LOAD
	if (dispatch_oss_copr(rec))     return;
#endif
#ifdef USE_SNDDRV_COMPRESS_OFFLOAD
	if (dispatch_snd_compress(rec)) return;
#endif
	if (dispatch_snd_seq(rec))      return;
}

static const struct ioctl sound_ioctls[] = {
	IOCTL(SNDRV_SEQ_IOCTL_PVERSION),
#ifdef SNDRV_SEQ_IOCTL_USER_PVERSION
	IOCTL(SNDRV_SEQ_IOCTL_USER_PVERSION),
#endif
	IOCTL(SNDRV_SEQ_IOCTL_CLIENT_ID),
	IOCTL(SNDRV_SEQ_IOCTL_SYSTEM_INFO),
	IOCTL(SNDRV_SEQ_IOCTL_RUNNING_MODE),
	IOCTL(SNDRV_SEQ_IOCTL_GET_CLIENT_INFO),
	IOCTL(SNDRV_SEQ_IOCTL_SET_CLIENT_INFO),
#ifdef SNDRV_SEQ_IOCTL_GET_CLIENT_UMP_INFO
	IOCTL(SNDRV_SEQ_IOCTL_GET_CLIENT_UMP_INFO),
	IOCTL(SNDRV_SEQ_IOCTL_SET_CLIENT_UMP_INFO),
#endif
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
#ifdef SNDRV_PCM_IOCTL_USER_PVERSION
	IOCTL(SNDRV_PCM_IOCTL_USER_PVERSION),
#endif
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
#ifdef SNDRV_RAWMIDI_IOCTL_USER_PVERSION
	IOCTL(SNDRV_RAWMIDI_IOCTL_USER_PVERSION),
#endif
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
	/* TREAD_OLD == TREAD on LP64; only TREAD64 is distinct on 64-bit */
#if defined(SNDRV_TIMER_IOCTL_TREAD64) && __BITS_PER_LONG == 64
	IOCTL(SNDRV_TIMER_IOCTL_TREAD64),
#endif
#ifdef SNDRV_TIMER_IOCTL_CREATE
	IOCTL(SNDRV_TIMER_IOCTL_CREATE),
#endif
#ifdef SNDRV_TIMER_IOCTL_TRIGGER
	IOCTL(SNDRV_TIMER_IOCTL_TRIGGER),
#endif
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
#ifdef SNDRV_CTL_IOCTL_UMP_NEXT_DEVICE
	IOCTL(SNDRV_CTL_IOCTL_UMP_NEXT_DEVICE),
#endif
#ifdef SNDRV_CTL_IOCTL_UMP_ENDPOINT_INFO
	IOCTL(SNDRV_CTL_IOCTL_UMP_ENDPOINT_INFO),
#endif
#ifdef SNDRV_CTL_IOCTL_UMP_BLOCK_INFO
	IOCTL(SNDRV_CTL_IOCTL_UMP_BLOCK_INFO),
#endif
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
#ifdef SNDRV_HDSPM_IOCTL_GET_PEAK_RMS
	IOCTL(SNDRV_HDSPM_IOCTL_GET_PEAK_RMS),
#endif
#ifdef SNDRV_HDSPM_IOCTL_GET_CONFIG
	IOCTL(SNDRV_HDSPM_IOCTL_GET_CONFIG),
#endif
#ifdef SNDRV_HDSPM_IOCTL_GET_LTC
	IOCTL(SNDRV_HDSPM_IOCTL_GET_LTC),
#endif
#ifdef SNDRV_HDSPM_IOCTL_GET_STATUS
	IOCTL(SNDRV_HDSPM_IOCTL_GET_STATUS),
#endif
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

	/* OSS PCM ioctls (/dev/dsp) */
	IOCTL(SNDCTL_DSP_RESET),
	IOCTL(SNDCTL_DSP_SYNC),
	IOCTL(SNDCTL_DSP_SPEED),
	IOCTL(SNDCTL_DSP_STEREO),
	IOCTL(SNDCTL_DSP_GETBLKSIZE),
	IOCTL(SNDCTL_DSP_SETFMT),
	IOCTL(SNDCTL_DSP_CHANNELS),
	IOCTL(SNDCTL_DSP_POST),
	IOCTL(SNDCTL_DSP_SUBDIVIDE),
	IOCTL(SNDCTL_DSP_SETFRAGMENT),
	IOCTL(SNDCTL_DSP_GETFMTS),
	IOCTL(SNDCTL_DSP_GETOSPACE),
	IOCTL(SNDCTL_DSP_GETISPACE),
	IOCTL(SNDCTL_DSP_NONBLOCK),
	IOCTL(SNDCTL_DSP_GETCAPS),
	IOCTL(SNDCTL_DSP_GETTRIGGER),
	IOCTL(SNDCTL_DSP_SETTRIGGER),
	IOCTL(SNDCTL_DSP_GETIPTR),
	IOCTL(SNDCTL_DSP_GETOPTR),
	IOCTL(SNDCTL_DSP_SETDUPLEX),
	IOCTL(SNDCTL_DSP_GETODELAY),
#ifdef SNDCTL_DSP_GETCHANNELMASK
	IOCTL(SNDCTL_DSP_GETCHANNELMASK),
#endif
#ifdef SNDCTL_DSP_BIND_CHANNEL
	IOCTL(SNDCTL_DSP_BIND_CHANNEL),
#endif
#ifdef SNDCTL_DSP_GETSPDIF
	IOCTL(SNDCTL_DSP_GETSPDIF),
#endif
#ifdef SNDCTL_DSP_SETSPDIF
	IOCTL(SNDCTL_DSP_SETSPDIF),
#endif
#ifdef SNDCTL_DSP_PROFILE
	IOCTL(SNDCTL_DSP_PROFILE),
#endif

	/* OSS DSP coprocessor (/dev/dsp[N], legacy SoundBlaster — type 'C') */
#ifdef SNDCTL_COPR_LOAD
	IOCTL(SNDCTL_COPR_LOAD),
	IOCTL(SNDCTL_COPR_RDATA),
	IOCTL(SNDCTL_COPR_RCODE),
	IOCTL(SNDCTL_COPR_WDATA),
	IOCTL(SNDCTL_COPR_WCODE),
	IOCTL(SNDCTL_COPR_RUN),
	IOCTL(SNDCTL_COPR_HALT),
	IOCTL(SNDCTL_COPR_SENDMSG),
	IOCTL(SNDCTL_COPR_RCVMSG),
#endif

	/* OSS mixer ioctls (/dev/mixer) */
	IOCTL(SOUND_MIXER_READ_VOLUME),
	IOCTL(SOUND_MIXER_READ_BASS),
	IOCTL(SOUND_MIXER_READ_TREBLE),
	IOCTL(SOUND_MIXER_READ_SYNTH),
	IOCTL(SOUND_MIXER_READ_PCM),
	IOCTL(SOUND_MIXER_READ_SPEAKER),
	IOCTL(SOUND_MIXER_READ_LINE),
	IOCTL(SOUND_MIXER_READ_MIC),
	IOCTL(SOUND_MIXER_READ_CD),
	IOCTL(SOUND_MIXER_READ_IMIX),
	IOCTL(SOUND_MIXER_READ_ALTPCM),
	IOCTL(SOUND_MIXER_READ_RECLEV),
	IOCTL(SOUND_MIXER_READ_IGAIN),
	IOCTL(SOUND_MIXER_READ_OGAIN),
	IOCTL(SOUND_MIXER_READ_LINE1),
	IOCTL(SOUND_MIXER_READ_LINE2),
	IOCTL(SOUND_MIXER_READ_LINE3),
	IOCTL(SOUND_MIXER_READ_RECSRC),
	IOCTL(SOUND_MIXER_READ_DEVMASK),
	IOCTL(SOUND_MIXER_READ_RECMASK),
	IOCTL(SOUND_MIXER_READ_STEREODEVS),
	IOCTL(SOUND_MIXER_READ_CAPS),
	IOCTL(SOUND_MIXER_WRITE_VOLUME),
	IOCTL(SOUND_MIXER_WRITE_BASS),
	IOCTL(SOUND_MIXER_WRITE_TREBLE),
	IOCTL(SOUND_MIXER_WRITE_SYNTH),
	IOCTL(SOUND_MIXER_WRITE_PCM),
	IOCTL(SOUND_MIXER_WRITE_SPEAKER),
	IOCTL(SOUND_MIXER_WRITE_LINE),
	IOCTL(SOUND_MIXER_WRITE_MIC),
	IOCTL(SOUND_MIXER_WRITE_CD),
	IOCTL(SOUND_MIXER_WRITE_IMIX),
	IOCTL(SOUND_MIXER_WRITE_ALTPCM),
	IOCTL(SOUND_MIXER_WRITE_RECLEV),
	IOCTL(SOUND_MIXER_WRITE_IGAIN),
	IOCTL(SOUND_MIXER_WRITE_OGAIN),
	IOCTL(SOUND_MIXER_WRITE_LINE1),
	IOCTL(SOUND_MIXER_WRITE_LINE2),
	IOCTL(SOUND_MIXER_WRITE_LINE3),
	IOCTL(SOUND_MIXER_WRITE_RECSRC),
	/* SOUND_MIXER_{MUTE,LOUD,ENHANCE} alias to SOUND_MIXER_NONE — skip
	 * the READ/WRITE wrappers; they collide with SOUND_MIXER_VOLUME. */
#ifdef SOUND_MIXER_AGC
	IOCTL(SOUND_MIXER_AGC),
#endif
#ifdef SOUND_MIXER_3DSE
	IOCTL(SOUND_MIXER_3DSE),
#endif
#ifdef SOUND_MIXER_ACCESS
	IOCTL(SOUND_MIXER_ACCESS),
#endif
#ifdef SOUND_MIXER_GETLEVELS
	IOCTL(SOUND_MIXER_GETLEVELS),
	IOCTL(SOUND_MIXER_SETLEVELS),
#endif
	IOCTL(SOUND_MIXER_INFO),
#ifdef OSS_GETVERSION
	IOCTL(OSS_GETVERSION),
#endif

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
