#pragma once

/*
 * UIO_FASTIOV / UIO_MAXIOV are the kernel-side fast-path and absolute
 * limits on iovec count.  <linux/uio.h> would redefine the libc's
 * struct iovec, so this wraps <sys/uio.h>, which supplies UIO_MAXIOV
 * on glibc; UIO_FASTIOV exists only in the kernel header.
 */
#include <sys/uio.h>

#ifndef UIO_FASTIOV
#define UIO_FASTIOV	8
#endif
#ifndef UIO_MAXIOV
#define UIO_MAXIOV	1024
#endif
