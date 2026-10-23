#pragma once

/*
 * <linux/watch_queue.h> pulls in <linux/fcntl.h>, whose struct
 * f_owner_ex and struct flock collide with the libc's <fcntl.h>, so the
 * fallbacks here stand without it.
 */
#include <fcntl.h>

#ifndef O_NOTIFICATION_PIPE
#define O_NOTIFICATION_PIPE	O_EXCL
#endif
