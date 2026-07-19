
#include <inttypes.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/soundcard.h>
#include <sound/asound.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "snd-internal.h"
#include "utils.h"

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

void sanitise_snd_hdspm(struct syscallrecord *rec)
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

void sanitise_oss_copr(struct syscallrecord *rec)
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

void sanitise_oss_dsp(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDCTL_DSP_SPEED: {
		int *rate = get_writable_struct(sizeof(int));
		if (rate) {
			*rate = pcm_rates[rnd_modulo_u32(pcm_rates_count)];
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

void sanitise_oss_mixer(struct syscallrecord *rec)
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

/* OSS PCM (/dev/dsp, type 'P') */
int dispatch_oss_dsp(struct syscallrecord *rec)
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
int dispatch_oss_mixer(struct syscallrecord *rec)
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
