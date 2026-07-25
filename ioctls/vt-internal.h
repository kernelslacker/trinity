#pragma once

/*
 * Per-family sanitisers carved out of ioctls/vt.c.  Each family owns
 * a switch on rec->a2 that fills argument slots for its ioctls and
 * falls through for numbers it does not recognise; the spine's
 * vt_sanitise() calls them in order.
 */

struct syscallrecord;

void vt_sanitise_kd(struct syscallrecord *rec);
