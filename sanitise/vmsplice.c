#include <stdlib.h>
#include "scrashme.h"

/*
 * asmlinkage long sys_vmsplice(int fd, const struct iovec __user *iov,
 *                unsigned long nr_segs, unsigned int flags)
 */

void sanitise_vmsplice(
	__unused__ unsigned long *fd,
	__unused__ unsigned long *a2,
	unsigned long *a3,
	__unused__ unsigned long *a4,
	__unused__ unsigned long *a5,
	__unused__ unsigned long *a6)
{
	*a3 = rand() % 1024;	/* UIO_MAXIOV */
}
