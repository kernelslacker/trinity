/*
 * SYSCALL_DEFINE4(vmsplice, int, fd, const struct iovec __user *, iov,
	 unsigned long, nr_segs, unsigned int, flags)
 */

#include <fcntl.h>
#include <limits.h>
#include <sys/uio.h>
#include "sanitise.h"
#include "trinity.h"
#include "compat.h"
#include "utils.h"

static unsigned long vmsplice_flags[] = {
	SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT,
};

static void post_vmsplice(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;
	if (ret < 0 || ret > SSIZE_MAX)
		post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_vmsplice = {
	.name = "vmsplice",
	.num_args = 4,
	.argtype = { [0] = ARG_FD_PIPE, [1] = ARG_IOVEC, [2] = ARG_IOVECLEN, [3] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "iov", [2] = "nr_segs", [3] = "flags" },
	.arg_params[3].list = ARGLIST(vmsplice_flags),
	.post = post_vmsplice,
	.group = GROUP_VM,
	.flags = NEED_ALARM,
};
