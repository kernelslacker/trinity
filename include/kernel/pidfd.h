#pragma once

/*
 * <linux/pidfd.h> pulls in <linux/fcntl.h>, which collides with the
 * libc's <fcntl.h>, so this includes neither.  Include it after
 * whichever of the two the file already uses; the fallback only names
 * O_NONBLOCK, which both define.
 */
#ifndef PIDFD_NONBLOCK
#define PIDFD_NONBLOCK	O_NONBLOCK
#endif
