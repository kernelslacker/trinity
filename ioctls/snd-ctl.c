
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

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "snd-internal.h"
#include "utils.h"

/* ctl */
IOCTL_SIZE_ASSERT(SNDRV_CTL_IOCTL_CARD_INFO, struct snd_ctl_card_info);
IOCTL_SIZE_ASSERT(SNDRV_CTL_IOCTL_ELEM_LIST, struct snd_ctl_elem_list);
IOCTL_SIZE_ASSERT(SNDRV_CTL_IOCTL_ELEM_INFO, struct snd_ctl_elem_info);
IOCTL_SIZE_ASSERT(SNDRV_CTL_IOCTL_ELEM_ADD, struct snd_ctl_elem_info);
IOCTL_SIZE_ASSERT(SNDRV_CTL_IOCTL_ELEM_REPLACE, struct snd_ctl_elem_info);
IOCTL_SIZE_ASSERT(SNDRV_CTL_IOCTL_ELEM_READ, struct snd_ctl_elem_value);
IOCTL_SIZE_ASSERT(SNDRV_CTL_IOCTL_ELEM_WRITE, struct snd_ctl_elem_value);
IOCTL_SIZE_ASSERT(SNDRV_CTL_IOCTL_ELEM_LOCK, struct snd_ctl_elem_id);
IOCTL_SIZE_ASSERT(SNDRV_CTL_IOCTL_ELEM_UNLOCK, struct snd_ctl_elem_id);
IOCTL_SIZE_ASSERT(SNDRV_CTL_IOCTL_ELEM_REMOVE, struct snd_ctl_elem_id);
IOCTL_SIZE_ASSERT(SNDRV_CTL_IOCTL_HWDEP_INFO, struct snd_hwdep_info);
IOCTL_SIZE_ASSERT(SNDRV_CTL_IOCTL_PCM_INFO, struct snd_pcm_info);
IOCTL_SIZE_ASSERT(SNDRV_CTL_IOCTL_RAWMIDI_INFO, struct snd_rawmidi_info);

static const unsigned int snd_ctl_elem_iface_vals[] = {
	SNDRV_CTL_ELEM_IFACE_CARD,
	SNDRV_CTL_ELEM_IFACE_HWDEP,
	SNDRV_CTL_ELEM_IFACE_MIXER,
	SNDRV_CTL_ELEM_IFACE_PCM,
	SNDRV_CTL_ELEM_IFACE_RAWMIDI,
	SNDRV_CTL_ELEM_IFACE_TIMER,
	SNDRV_CTL_ELEM_IFACE_SEQUENCER,
};

/*
 * Local copies of stream-direction tables.  The PCM and RAWMIDI classes
 * carry their own; the CTL class needs its own for the *_INFO ioctls it
 * exposes.  Each per-class TU keeps its own static copy under a
 * distinct name so classes can be carved / removed independently and
 * the no-multiply-defined-symbols gate stays clean.
 */
static const int ctl_pcm_stream_vals[] = {
	SNDRV_PCM_STREAM_PLAYBACK,
	SNDRV_PCM_STREAM_CAPTURE,
};

static const int ctl_rawmidi_stream_vals[] = {
	SNDRV_RAWMIDI_STREAM_OUTPUT,
	SNDRV_RAWMIDI_STREAM_INPUT,
};

static void fill_snd_ctl_elem_id(struct snd_ctl_elem_id *id)
{
	id->numid = RAND_BOOL() ? 0 : rnd_modulo_u32(64);
	id->iface = RAND_ARRAY(snd_ctl_elem_iface_vals);
	id->device = rnd_modulo_u32(8);
	id->subdevice = rnd_modulo_u32(8);
	id->index = rnd_modulo_u32(8);
}

static void snd_ctl_sanitise_card_info(struct syscallrecord *rec)
{
	struct snd_ctl_card_info *info = get_writable_struct(sizeof(*info));
	if (info) {
		memset(info, 0, sizeof(*info));
		rec->a3 = (unsigned long) info;
	}
}

static void snd_ctl_sanitise_elem_list(struct syscallrecord *rec)
{
	struct snd_ctl_elem_list *list = get_writable_struct(sizeof(*list));
	if (list) {
		memset(list, 0, sizeof(*list));
		unsigned int space = rnd_modulo_u32(16) + 1;
		void *pids = get_writable_struct(space * sizeof(*list->pids));
		list->offset = rnd_modulo_u32(64);
		if (pids) {
			list->pids = pids;
			list->space = space;
		} else {
			list->pids = NULL;
			list->space = 0;
		}
		rec->a3 = (unsigned long) list;
	}
}

static void snd_ctl_sanitise_elem_info(struct syscallrecord *rec)
{
	struct snd_ctl_elem_info *info = get_writable_struct(sizeof(*info));
	if (info) {
		memset(info, 0, sizeof(*info));
		fill_snd_ctl_elem_id(&info->id);
		rec->a3 = (unsigned long) info;
	}
}

static void snd_ctl_sanitise_elem_value(struct syscallrecord *rec)
{
	struct snd_ctl_elem_value *val = get_writable_struct(sizeof(*val));
	if (val) {
		memset(val, 0, sizeof(*val));
		fill_snd_ctl_elem_id(&val->id);
		rec->a3 = (unsigned long) val;
	}
}

static void snd_ctl_sanitise_elem_id(struct syscallrecord *rec)
{
	struct snd_ctl_elem_id *id = get_writable_struct(sizeof(*id));
	if (id) {
		memset(id, 0, sizeof(*id));
		fill_snd_ctl_elem_id(id);
		rec->a3 = (unsigned long) id;
	}
}

static void snd_ctl_sanitise_tlv(struct syscallrecord *rec)
{
	unsigned int datalen = (rnd_modulo_u32(8) + 1) * 4;
	/* snd_ctl_tlv has a flexible array member, allocate with data */
	struct snd_ctl_tlv *tlv = get_writable_struct(sizeof(*tlv) + datalen);
	if (tlv) {
		memset(tlv, 0, sizeof(*tlv) + datalen);
		tlv->numid = rnd_modulo_u32(64);
		tlv->length = datalen;
		rec->a3 = (unsigned long) tlv;
	}
}

static void snd_ctl_sanitise_next_device(struct syscallrecord *rec)
{
	int *dev = get_writable_struct(sizeof(int));
	if (dev) {
		*dev = (int)(rnd_modulo_u32(8)) - 1;	/* -1 to get first, 0-7 otherwise */
		rec->a3 = (unsigned long) dev;
	}
}

static void snd_ctl_sanitise_hwdep_info(struct syscallrecord *rec)
{
	struct snd_hwdep_info *info = get_writable_struct(sizeof(*info));
	if (info) {
		memset(info, 0, sizeof(*info));
		info->device = rnd_modulo_u32(8);
		rec->a3 = (unsigned long) info;
	}
}

static void snd_ctl_sanitise_pcm_info(struct syscallrecord *rec)
{
	struct snd_pcm_info *info = get_writable_struct(sizeof(*info));
	if (info) {
		memset(info, 0, sizeof(*info));
		info->device = rnd_modulo_u32(8);
		info->subdevice = rnd_modulo_u32(8);
		info->stream = RAND_ARRAY(ctl_pcm_stream_vals);
		rec->a3 = (unsigned long) info;
	}
}

static void snd_ctl_sanitise_rawmidi_info(struct syscallrecord *rec)
{
	struct snd_rawmidi_info *info = get_writable_struct(sizeof(*info));
	if (info) {
		memset(info, 0, sizeof(*info));
		info->device = rnd_modulo_u32(8);
		info->subdevice = rnd_modulo_u32(8);
		info->stream = RAND_ARRAY(ctl_rawmidi_stream_vals);
		rec->a3 = (unsigned long) info;
	}
}

static void snd_ctl_sanitise_prefer_subdevice(struct syscallrecord *rec)
{
	int *val = get_writable_struct(sizeof(int));
	if (val) {
		*val = rnd_modulo_u32(8);
		rec->a3 = (unsigned long) val;
	}
}

static void snd_ctl_sanitise_subscribe_events(struct syscallrecord *rec)
{
	int *sub = get_writable_struct(sizeof(int));
	if (sub) {
		*sub = RAND_BOOL();
		rec->a3 = (unsigned long) sub;
	}
}

void sanitise_snd_ctl(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_CTL_IOCTL_CARD_INFO:
		snd_ctl_sanitise_card_info(rec);
		break;
	case SNDRV_CTL_IOCTL_ELEM_LIST:
		snd_ctl_sanitise_elem_list(rec);
		break;
	case SNDRV_CTL_IOCTL_ELEM_INFO:
	case SNDRV_CTL_IOCTL_ELEM_ADD:
	case SNDRV_CTL_IOCTL_ELEM_REPLACE:
		snd_ctl_sanitise_elem_info(rec);
		break;
	case SNDRV_CTL_IOCTL_ELEM_READ:
	case SNDRV_CTL_IOCTL_ELEM_WRITE:
		snd_ctl_sanitise_elem_value(rec);
		break;
	case SNDRV_CTL_IOCTL_ELEM_LOCK:
	case SNDRV_CTL_IOCTL_ELEM_UNLOCK:
	case SNDRV_CTL_IOCTL_ELEM_REMOVE:
		snd_ctl_sanitise_elem_id(rec);
		break;
	case SNDRV_CTL_IOCTL_TLV_READ:
	case SNDRV_CTL_IOCTL_TLV_WRITE:
	case SNDRV_CTL_IOCTL_TLV_COMMAND:
		snd_ctl_sanitise_tlv(rec);
		break;
	case SNDRV_CTL_IOCTL_HWDEP_NEXT_DEVICE:
	case SNDRV_CTL_IOCTL_PCM_NEXT_DEVICE:
	case SNDRV_CTL_IOCTL_RAWMIDI_NEXT_DEVICE:
		snd_ctl_sanitise_next_device(rec);
		break;
	case SNDRV_CTL_IOCTL_HWDEP_INFO:
		snd_ctl_sanitise_hwdep_info(rec);
		break;
	case SNDRV_CTL_IOCTL_PCM_INFO:
		snd_ctl_sanitise_pcm_info(rec);
		break;
	case SNDRV_CTL_IOCTL_RAWMIDI_INFO:
		snd_ctl_sanitise_rawmidi_info(rec);
		break;
	case SNDRV_CTL_IOCTL_PCM_PREFER_SUBDEVICE:
	case SNDRV_CTL_IOCTL_RAWMIDI_PREFER_SUBDEVICE:
	case SNDRV_CTL_IOCTL_POWER:
		snd_ctl_sanitise_prefer_subdevice(rec);
		break;
	case SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS:
		snd_ctl_sanitise_subscribe_events(rec);
		break;
	default:
		break;
	}
}

int dispatch_snd_ctl(struct syscallrecord *rec)
{
	switch (rec->a2) {
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
		return 1;
	}
	return 0;
}
