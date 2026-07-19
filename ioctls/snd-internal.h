#pragma once

/*
 * Internal entry points shared between snd.c (spine) and the per-class
 * TUs that were carved out of it.  Each carved class exposes exactly
 * two symbols: a sanitiser and a dispatcher.  The spine's
 * sound_sanitise() walks the dispatchers in order.
 */

struct syscallrecord;

void sanitise_snd_ctl(struct syscallrecord *rec);
int  dispatch_snd_ctl(struct syscallrecord *rec);
