
#ifdef USE_SNDDRV_COMPRESS_OFFLOAD

#include <linux/types.h>
#include <linux/ioctl.h>
#include <sound/asound.h>
#include <sound/compress_offload.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "snd-internal.h"
#include "utils.h"

/* compress offload */
IOCTL_SIZE_ASSERT(SNDRV_COMPRESS_GET_CAPS, struct snd_compr_caps);
IOCTL_SIZE_ASSERT(SNDRV_COMPRESS_GET_CODEC_CAPS, struct snd_compr_codec_caps);
IOCTL_SIZE_ASSERT(SNDRV_COMPRESS_SET_PARAMS, struct snd_compr_params);
IOCTL_SIZE_ASSERT(SNDRV_COMPRESS_GET_PARAMS, struct snd_codec);
IOCTL_SIZE_ASSERT(SNDRV_COMPRESS_TSTAMP, struct snd_compr_tstamp);
IOCTL_SIZE_ASSERT(SNDRV_COMPRESS_AVAIL, struct snd_compr_avail);

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
	c->sample_rate = pcm_rates[rnd_modulo_u32(pcm_rates_count)];
	c->bit_rate = (rnd_modulo_u32(320) + 32) * 1000;
	/* leave profile/level/format/options zero — kernel validates per codec */
}

void sanitise_snd_compress(struct syscallrecord *rec)
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

/* snd-compress (compressed audio offload) */
int dispatch_snd_compress(struct syscallrecord *rec)
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

#endif /* USE_SNDDRV_COMPRESS_OFFLOAD */
