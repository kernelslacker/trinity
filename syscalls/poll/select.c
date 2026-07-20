/*
 * SYSCALL_DEFINE5(select, int, n, fd_set __user *, inp, fd_set __user *, outp,
	fd_set __user *, exp, struct timeval __user *, tvp)
 */
#include <sys/time.h>

#include "fd.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Pick one bit-position within [0, nfds) for the select(2) / pselect6(2)
 * fd_set.  Distribution:
 *   ~60%  the live fd number of a tracked pollable fd_type (so
 *         do_select walks into a real ->poll handler with a wait
 *         queue rather than a regular-file shortcut)
 *   ~30%  legacy random bit position within [0, nfds)
 *   ~10%  a deliberately-high bit unlikely to map to an open fd,
 *         exercising the EBADF leg of do_select()
 *
 * Returns -1 when the pollable bucket fires but the chosen fd is
 * outside the fd_set's [0, nfds) range or no candidate is available;
 * the caller skips FD_SET for that slot.
 */
static int pick_select_bit(unsigned int nfds)
{
	unsigned int roll = rnd_modulo_u32(100);
	int fd;

	if (roll < 60) {
		fd = get_pollable_random_fd();
		if (fd < 0 || (unsigned int) fd >= nfds)
			return -1;
		return fd;
	}

	if (roll < 90)
		return (int) rnd_modulo_u32(nfds);

	/* invalid bucket: a bit position in the upper half of the bitmap
	 * that is unlikely to correspond to a currently-open fd. */
	if (nfds > 256)
		return (int)(256 + rnd_modulo_u32(nfds - 256));
	return (int) rnd_modulo_u32(nfds);
}

/*
 * The post handler needs to know nfds to validate the success-path
 * retval against the 3 * nfds upper bound.  Stash it in rec->post_state
 * wrapped in a magic-cookie struct so a sibling scribble of post_state
 * cannot pass off arbitrary bytes as a count.  All four syscall-visible
 * buffers (the three fd_sets and the timeval) live in the
 * get_writable_address() pool, which the kernel can write into directly
 * and which the pool reclaims on its own -- no heap pointer needs
 * snapshotting for deferred-free.
 */
#define SELECT_POST_STATE_MAGIC	0x53454C43UL	/* "SELC" */
struct select_post_state {
	unsigned long magic;
	unsigned int nfds;
};

static void sanitise_select(struct syscallrecord *rec)
{
	struct select_post_state *snap;
	unsigned int nfds, i, nset;

	struct timeval *tv;
	fd_set *rfds, *wfds, *exfds;

	nfds = rnd_modulo_u32(1023) + 1;
	rec->a1 = nfds;

	rfds = get_writable_address(sizeof(fd_set));
	wfds = get_writable_address(sizeof(fd_set));
	exfds = get_writable_address(sizeof(fd_set));

	if (rfds == NULL || wfds == NULL || exfds == NULL) {
		rec->a2 = (unsigned long) rfds;
		rec->a3 = (unsigned long) wfds;
		rec->a4 = (unsigned long) exfds;
		rec->a5 = 0;
		return;
	}

	FD_ZERO(rfds);
	FD_ZERO(wfds);
	FD_ZERO(exfds);

	nset = rnd_modulo_u32(10);
	/*
	 * Pick the bits to set with the same coverage bias as poll(2):
	 *   ~60% — use the actual fd number of a tracked pollable fd_type
	 *          (pipe, eventfd, timerfd, signalfd, inotify, fanotify,
	 *          socket).  do_select then walks into each fd's ->poll
	 *          handler and parks on the real wait queue instead of
	 *          short-circuiting on a regular file.
	 *   ~30% — legacy random bit position.
	 *   ~10% — an explicitly high bit unlikely to map to an open fd,
	 *          so the EBADF rejection path inside do_select() stays
	 *          exercised.
	 *
	 * Each candidate bit still passes through fd_poll_can_block() so
	 * a collision with a FUSE / uffd / io_uring / vCPU / pidfd handle
	 * cannot wedge the child in TASK_UNINTERRUPTIBLE.
	 */
	for (i = 0; i < nset; i++) {
		int rfd, wfd, efd;

		rfd = pick_select_bit(nfds);
		wfd = pick_select_bit(nfds);
		efd = pick_select_bit(nfds);

		if (rfd >= 0) {
			if (!fd_poll_can_block(rfd))
				FD_SET(rfd, rfds);
			else
				__atomic_add_fetch(&shm->stats.epoll_volatility.blocking_poll_skipped, 1,
						   __ATOMIC_RELAXED);
		}
		if (wfd >= 0) {
			if (!fd_poll_can_block(wfd))
				FD_SET(wfd, wfds);
			else
				__atomic_add_fetch(&shm->stats.epoll_volatility.blocking_poll_skipped, 1,
						   __ATOMIC_RELAXED);
		}
		if (efd >= 0) {
			if (!fd_poll_can_block(efd))
				FD_SET(efd, exfds);
			else
				__atomic_add_fetch(&shm->stats.epoll_volatility.blocking_poll_skipped, 1,
						   __ATOMIC_RELAXED);
		}
	}

	rec->a2 = (unsigned long) rfds;
	rec->a3 = (unsigned long) wfds;
	rec->a4 = (unsigned long) exfds;

	avoid_shared_buffer_inout(&rec->a2, sizeof(fd_set));
	avoid_shared_buffer_inout(&rec->a3, sizeof(fd_set));
	avoid_shared_buffer_inout(&rec->a4, sizeof(fd_set));

	/* Set a really short timeout */
	tv = get_writable_address(sizeof(struct timeval));
	if (tv == NULL) {
		rec->a5 = 0;
	} else {
		tv->tv_sec = 0;
		tv->tv_usec = 10;
		rec->a5 = (unsigned long) tv;
		avoid_shared_buffer_inout(&rec->a5, sizeof(struct timeval));
	}

	/*
	 * Stash nfds for the post handler's retval bound check.  The snap
	 * itself is a small heap allocation (not a syscall-visible buffer)
	 * and carries a magic cookie; install it through the ownership
	 * table so the post handler can run post_state_claim_owned() and
	 * prove ownership before dereferencing any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = SELECT_POST_STATE_MAGIC;
	snap->nfds = nfds;
	post_state_install(rec, snap);
}

static void post_select(struct syscallrecord *rec)
{
	struct select_post_state *snap;
	unsigned long retval = rec->retval;

	rec->a2 = 0;
	rec->a3 = 0;
	rec->a4 = 0;
	rec->a5 = 0;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, SELECT_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	/*
	 * Kernel ABI: select(2) on success returns the total count of ready
	 * fds across the read/write/exception sets — fs/select.c::do_select()
	 * walks each bitmap of size nfds independently and sums set-bit
	 * counts across all three, so a single fd present in all three sets
	 * contributes 3 to the return. The upper bound is therefore 3 * nfds,
	 * not nfds. Failure returns -1UL with EBADF/EFAULT/EINTR/EINVAL/ENOMEM.
	 * Anything > 3 * nfds (excluding -1UL) is a structural ABI regression:
	 * a sign-extension tear, a torn write of the count by a parallel
	 * signal-restart path, or -errno leaking through the success slot.
	 */
	if ((long) retval != -1L && retval > 3UL * snap->nfds) {
		outputerr("post_select: rejected retval=0x%lx > 3*nfds=%u\n",
			  retval, 3 * snap->nfds);
		post_handler_corrupt_ptr_bump(rec, NULL);
		/* fall through to release the snap */
	}

	post_state_release(rec, snap);
}

struct syscallentry syscall_select = {
	.name = "select",
	.num_args = 5,
	.argtype = { [0] = ARG_LEN, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS, [4] = ARG_ADDRESS },
	.argname = { [0] = "n", [1] = "inp", [2] = "outp", [3] = "exp", [4] = "tvp" },
	.sanitise = sanitise_select,
	.post = post_select,
	.group = GROUP_VFS,
	.flags = NEED_ALARM,
	.rettype = RET_BORING,
};
