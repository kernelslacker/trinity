/*
 * SYSCALL_DEFINE4(vmsplice, int, fd, const struct iovec __user *, iov,
	 unsigned long, nr_segs, unsigned int, flags)
 */

#include <errno.h>
#include <limits.h>
#include <sys/uio.h>
#include <fcntl.h>
#include "arch.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/splice.h"
static unsigned long vmsplice_flags[] = {
	SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT,
};

static void post_vmsplice(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;
	struct iovec *iov;
	unsigned long nr_segs, i;

	if (ret == -1L)
		goto check_kernel_range;
	if (ret < 0 || ret > SSIZE_MAX)
		post_handler_corrupt_ptr_bump(rec, NULL);

check_kernel_range:
	/*
	 * If any iov entry carries a kernel-range base the kernel must
	 * return -EFAULT: a correct access_ok() rejects addresses above
	 * TASK_SIZE before the page-table walk.  A non-EFAULT return
	 * from a kernel-range base means access_ok was skipped or
	 * bypassed and is itself a finding.
	 */
	iov = (struct iovec *) rec->a2;
	nr_segs = rec->a3;
	if (iov == NULL || nr_segs == 0)
		return;
	if (nr_segs > UIO_MAXIOV)
		nr_segs = UIO_MAXIOV;
	for (i = 0; i < nr_segs; i++) {
		unsigned long base = (unsigned long) iov[i].iov_base;

		if (base < (unsigned long) KERNEL_ADDR)
			continue;
		/* kernel-range base: must have EFAULTed */
		if (rec->errno_post != EFAULT)
			post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}
}

struct syscallentry syscall_vmsplice = {
	.name = "vmsplice",
	.num_args = 4,
	.argtype = { [0] = ARG_FD_PIPE, [1] = ARG_IOVEC_IN, [2] = ARG_IOVECLEN, [3] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "iov", [2] = "nr_segs", [3] = "flags" },
	.arg_params[3].list = ARGLIST(vmsplice_flags),
	.post = post_vmsplice,
	.group = GROUP_VM,
	.flags = NEED_ALARM,
	.rettype = RET_NUM_BYTES,
};
