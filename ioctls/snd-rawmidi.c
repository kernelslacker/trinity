
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

/* rawmidi */
IOCTL_SIZE_ASSERT(SNDRV_RAWMIDI_IOCTL_INFO, struct snd_rawmidi_info);
IOCTL_SIZE_ASSERT(SNDRV_RAWMIDI_IOCTL_PARAMS, struct snd_rawmidi_params);
IOCTL_SIZE_ASSERT(SNDRV_RAWMIDI_IOCTL_STATUS, struct snd_rawmidi_status);

static const int snd_rawmidi_stream_vals[] = {
	SNDRV_RAWMIDI_STREAM_OUTPUT,
	SNDRV_RAWMIDI_STREAM_INPUT,
};

void sanitise_snd_rawmidi(struct syscallrecord *rec)
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

int dispatch_snd_rawmidi(struct syscallrecord *rec)
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
