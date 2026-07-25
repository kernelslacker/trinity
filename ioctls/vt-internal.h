#pragma once

/*
 * Per-family sanitisers carved out of ioctls/vt.c.  Each family owns
 * a switch on rec->a2 that fills argument slots for its ioctls and
 * falls through for numbers it does not recognise; the spine's
 * vt_sanitise() calls them in order.
 */

/*
 * HAVE_TERMIOS2 shim: distros without termios2 in their libc headers
 * still get TCGETS2/TCSETS2/... from the kernel headers, whose
 * _IOR/_IOW encoding embeds sizeof(struct termios2).  The struct must
 * therefore be visible wherever those request numbers are named --
 * that is both the spine (vt_ioctls[]) and the tioc TU.
 */
#ifndef HAVE_TERMIOS2
typedef unsigned char   cc_t;
typedef unsigned int    speed_t;
typedef unsigned int    tcflag_t;

#ifndef NCCS
#define NCCS 19
#endif
struct termios2 {
        tcflag_t c_iflag;               /* input mode flags */
        tcflag_t c_oflag;               /* output mode flags */
        tcflag_t c_cflag;               /* control mode flags */
        tcflag_t c_lflag;               /* local mode flags */
        cc_t c_line;                    /* line discipline */
        cc_t c_cc[NCCS];                /* control characters */
        speed_t c_ispeed;               /* input speed */
        speed_t c_ospeed;               /* output speed */
};
#endif

struct syscallrecord;

void vt_sanitise_kd(struct syscallrecord *rec);
void vt_sanitise_tioc(struct syscallrecord *rec);
void vt_sanitise_unimap(struct syscallrecord *rec);
