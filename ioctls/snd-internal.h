#pragma once

/*
 * Internal entry points shared between snd.c (spine) and the per-class
 * TUs that were carved out of it.  Each carved class exposes exactly
 * two symbols: a sanitiser and a dispatcher.  The spine's
 * sound_sanitise() walks the dispatchers in order.
 */

struct syscallrecord;
struct snd_timer_id;

void sanitise_snd_ctl(struct syscallrecord *rec);
int  dispatch_snd_ctl(struct syscallrecord *rec);

void sanitise_snd_pcm(struct syscallrecord *rec);
int  dispatch_snd_pcm(struct syscallrecord *rec);

void sanitise_snd_rawmidi(struct syscallrecord *rec);
int  dispatch_snd_rawmidi(struct syscallrecord *rec);

void sanitise_snd_timer(struct syscallrecord *rec);
int  dispatch_snd_timer(struct syscallrecord *rec);
void fill_snd_timer_id(struct snd_timer_id *tid);

void sanitise_snd_seq(struct syscallrecord *rec);
int  dispatch_snd_seq(struct syscallrecord *rec);

void sanitise_snd_hdspm(struct syscallrecord *rec);
int  dispatch_snd_hdspm(struct syscallrecord *rec);
void sanitise_oss_copr(struct syscallrecord *rec);
void sanitise_oss_dsp(struct syscallrecord *rec);
void sanitise_oss_mixer(struct syscallrecord *rec);
int  dispatch_oss_dsp(struct syscallrecord *rec);
int  dispatch_oss_mixer(struct syscallrecord *rec);

#ifdef USE_SNDDRV_COMPRESS_OFFLOAD
void sanitise_snd_compress(struct syscallrecord *rec);
int  dispatch_snd_compress(struct syscallrecord *rec);
#endif

/*
 * pcm_rates[] is shared between the PCM class (snd-pcm.c) and the OSS
 * DSP / compressed-offload paths still in snd.c.  Definition lives in
 * snd.c; pcm_rates_count carries the element count so callers do not
 * need the array's storage size visible.
 */
extern const unsigned int pcm_rates[];
extern const unsigned int pcm_rates_count;
