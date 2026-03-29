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
	.argtype = { [0] = ARG_FD_PIPE, [1] = ARG_IOVEC, [2] = ARG_IOVECLEN, [3] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "iov", [2] = "nr_segs", [3] = "flags" },
	.arg_params[3].list = ARGLIST(vmsplice_flags),
	.group = GROUP_VM,
	.flags = NEED_ALARM,
};
