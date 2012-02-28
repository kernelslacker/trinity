/*
 * SYSCALL_DEFINE4(vmsplice, int, fd, const struct iovec __user *, iov,
	 unsigned long, nr_segs, unsigned int, flags)
 */

#include <fcntl.h>
#include <sys/uio.h>
#include <stdlib.h>

#include "trinity.h"
#include "sanitise.h"

static void sanitise_vmsplice(
	__unused__ unsigned long *fd,
	__unused__ unsigned long *a2,
	unsigned long *a3,
	__unused__ unsigned long *a4,
	__unused__ unsigned long *a5,
	__unused__ unsigned long *a6)
{
	*a3 = rand() % UIO_MAXIOV;
}

struct syscall syscall_vmsplice = {
	.name = "vmsplice",
	.num_args = 4,
	.sanitise = sanitise_vmsplice,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "iov",
	.arg2type = ARG_ADDRESS,
	.arg3name = "nr_segs",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = {
		.num = 4,
		.values = { SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT },
	}
};
