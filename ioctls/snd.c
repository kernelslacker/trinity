
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

/* ump */
IOCTL_SIZE_ASSERT(SNDRV_UMP_IOCTL_ENDPOINT_INFO, struct snd_ump_endpoint_info);
IOCTL_SIZE_ASSERT(SNDRV_UMP_IOCTL_BLOCK_INFO, struct snd_ump_block_info);
#ifdef SNDRV_CTL_IOCTL_UMP_ENDPOINT_INFO
IOCTL_SIZE_ASSERT(SNDRV_CTL_IOCTL_UMP_ENDPOINT_INFO, struct snd_ump_endpoint_info);
#endif
#ifdef SNDRV_CTL_IOCTL_UMP_BLOCK_INFO
IOCTL_SIZE_ASSERT(SNDRV_CTL_IOCTL_UMP_BLOCK_INFO, struct snd_ump_block_info);
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

const unsigned int pcm_rates[] = {
	8000, 11025, 16000, 22050, 32000, 44100, 48000, 64000, 88200, 96000, 192000,
};
const unsigned int pcm_rates_count = ARRAY_SIZE(pcm_rates);

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
