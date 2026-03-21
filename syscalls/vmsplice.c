/*
 * SYSCALL_DEFINE4(vmsplice, int, fd, const struct iovec __user *, iov,
	 unsigned long, nr_segs, unsigned int, flags)
 */

#include <fcntl.h>
#include <sys/uio.h>
#include "sanitise.h"
#include "compat.h"

static unsigned long vmsplice_flags[] = {
	SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT,
};

struct syscallentry syscall_vmsplice = {
	.name = "vmsplice",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD_PIPE,
	.arg2name = "iov",
	.arg2type = ARG_IOVEC,
	.arg3name = "nr_segs",
	.arg3type = ARG_IOVECLEN,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = ARGLIST(vmsplice_flags),
	.group = GROUP_VM,
	.flags = NEED_ALARM,
};
