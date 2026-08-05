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
	 * If any iov entry carries a kernel-range base and the syscall
	 * returned >= 0, access_ok was skipped or bypassed: a correct
	 * kernel rejects kernel-space addresses before the page-table
	 * walk and returns -EFAULT (or an earlier -errno).  Success
	 * with a kernel-range base is a finding.
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
		/*
		 * kernel-range base found.  The correct discriminator is
		 * ret >= 0, NOT errno != EFAULT.
		 *
		 * Why: vmsplice() can return -EINVAL (bad flags), -EBADF
		 * (bad/closed fd), or -EINVAL (nr_segs > UIO_MAXIOV or
		 * negative iov_len) before import_iovec() ever reaches
		 * segment i and its access_ok() check.  All of those
		 * early-exit paths leave errno_post != EFAULT while the
		 * kernel did nothing wrong — gating on errno != EFAULT
		 * fires false positives on every stale pipe fd (EBADF),
		 * which is routine when trinity recycles fds.
		 *
		 * A genuine access_ok bypass with KERNEL_ADDR (mapped
		 * kernel .text) succeeds: copy_from_iter() under STAC
		 * reads the page and returns a positive byte count.
		 * A correct kernel performs access_ok(), rejects the
		 * address, and returns -EFAULT.  So bypass → ret >= 0,
		 * correct → ret < 0.  EFAULT vs other-errno is not a
		 * signal at all.
		 *
		 * Write-direction note: on IOV_KERNEL_WRITE paths,
		 * KERNEL_ADDR points at read-only .text; a bypassing
		 * write will fault on the page-table permission check
		 * and return EFAULT anyway — indistinguishable from
		 * the correct path.  A write-direction oracle would need
		 * a writable kernel address (e.g. direct-map) rather
		 * than KERNEL_ADDR.  Do not extend this oracle to the
		 * other IOV_KERNEL_READ syscalls without that change.
		 */
		if (ret >= 0)
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
