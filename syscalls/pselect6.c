/*
 * SYSCALL_DEFINE6(pselect6, int, n, fd_set __user *, inp, fd_set __user *, outp,
	fd_set __user *, exp, struct timespec __user *, tsp,
	void __user *, sig)
 */
#include <sys/time.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "fd.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Pick one bit-position within [0, nfds) for the pselect6(2) fd_set
 * with the same 60 / 30 / 10 bias as the sibling select(2) sanitiser:
 * tracked pollable fd_type, legacy random bit, or deliberately-high
 * bit to keep the EBADF leg of do_select() warm.  Returns -1 when no
 * usable candidate is available (caller skips FD_SET for that slot).
 */
static int pick_pselect6_bit(unsigned int nfds)
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

	if (nfds > 256)
		return (int)(256 + rnd_modulo_u32(nfds - 256));
	return (int) rnd_modulo_u32(nfds);
}

/*
 * The post handler needs to know nfds to validate the success-path
 * retval against the 3 * nfds upper bound.  Stash it in rec->post_state
 * wrapped in a magic-cookie struct so a sibling scribble of post_state
 * cannot pass off arbitrary bytes as a count.  All five syscall-visible
 * buffers (the three fd_sets, the timespec, and the sigmask) live in
 * the get_writable_address() pool, which the kernel can write into
 * directly and which the pool reclaims on its own -- no heap pointer
 * needs snapshotting for deferred-free.
 */
#define PSELECT6_POST_STATE_MAGIC	0x50534C36UL	/* "PSL6" */
struct pselect6_post_state {
	unsigned long magic;
	unsigned int nfds;
};

static void sanitise_pselect6(struct syscallrecord *rec)
{
	struct pselect6_post_state *snap;
	unsigned int nfds, i, nset;

	struct timespec *ts;
	sigset_t *sigmask;
	fd_set *rfds, *wfds, *exfds;

	nfds = (rand32() % 1023) + 1;
	rec->a1 = nfds;

	rfds = get_writable_address(sizeof(fd_set));
	wfds = get_writable_address(sizeof(fd_set));
	exfds = get_writable_address(sizeof(fd_set));

	if (rfds == NULL || wfds == NULL || exfds == NULL) {
		rec->a2 = (unsigned long) rfds;
		rec->a3 = (unsigned long) wfds;
		rec->a4 = (unsigned long) exfds;
		rec->a5 = 0;
		rec->a6 = 0;
		return;
	}

	FD_ZERO(rfds);
	FD_ZERO(wfds);
	FD_ZERO(exfds);

	nset = rand32() % 10;
	/*
	 * Pick the bits to set with the same coverage bias as poll(2) /
	 * select(2): ~60% tracked pollable fd_type fd numbers (real wait
	 * queues), ~30% legacy random bit positions, ~10% deliberately
	 * high invalid bits to keep the EBADF leg of do_select() warm.
	 * Each candidate still passes through fd_poll_can_block() so a
	 * collision with a FUSE / uffd / io_uring / vCPU / pidfd handle
	 * cannot wedge the child in TASK_UNINTERRUPTIBLE.
	 */
	for (i = 0; i < nset; i++) {
		int rfd, wfd, efd;

		rfd = pick_pselect6_bit(nfds);
		wfd = pick_pselect6_bit(nfds);
		efd = pick_pselect6_bit(nfds);

		if (rfd >= 0) {
			if (!fd_poll_can_block(rfd))
				FD_SET(rfd, rfds);
			else
				__atomic_add_fetch(&shm->stats.epoll_blocking_poll_skipped, 1,
						   __ATOMIC_RELAXED);
		}
		if (wfd >= 0) {
			if (!fd_poll_can_block(wfd))
				FD_SET(wfd, wfds);
			else
				__atomic_add_fetch(&shm->stats.epoll_blocking_poll_skipped, 1,
						   __ATOMIC_RELAXED);
		}
		if (efd >= 0) {
			if (!fd_poll_can_block(efd))
				FD_SET(efd, exfds);
			else
				__atomic_add_fetch(&shm->stats.epoll_blocking_poll_skipped, 1,
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
	ts = get_writable_address(sizeof(struct timespec));
	if (ts == NULL) {
		rec->a5 = 0;
	} else {
		ts->tv_sec = 0;
		ts->tv_nsec = 10000;
		rec->a5 = (unsigned long) ts;
	}

	/*
	 * Hand the kernel a real (zeroed) sigmask buffer rather than NULL so
	 * the copy_from_user path on the kernel side still has something to
	 * read.  An empty mask is semantically equivalent to NULL for the
	 * purposes of pselect6's signal-blocking dance.
	 */
	sigmask = get_writable_address(sizeof(sigset_t));
	if (sigmask == NULL) {
		rec->a6 = 0;
	} else {
		memset(sigmask, 0, sizeof(sigset_t));
		rec->a6 = (unsigned long) sigmask;
	}

	/*
	 * Stash nfds for the post handler's retval bound check.  The snap
	 * itself is a small heap allocation (not a syscall-visible buffer),
	 * carries a magic cookie, and is released via deferred_freeptr()
	 * after the post handler runs.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = PSELECT6_POST_STATE_MAGIC;
	snap->nfds = nfds;
	rec->post_state = (unsigned long) snap;
}

static void post_pselect6(struct syscallrecord *rec)
{
	struct pselect6_post_state *snap = (struct pselect6_post_state *) rec->post_state;
	unsigned long retval = rec->retval;

	rec->a2 = 0;
	rec->a3 = 0;
	rec->a4 = 0;
	rec->a5 = 0;
	rec->a6 = 0;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_pselect6: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as a
	 * pselect6_post_state.  A cookie mismatch means snap does not point
	 * at our struct -- abandon rather than feed wild bytes into the
	 * inner-pointer free path.
	 */
	if (snap->magic != PSELECT6_POST_STATE_MAGIC) {
		outputerr("post_pselect6: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return;
	}

	/*
	 * Kernel ABI: pselect6(2) on success returns the total count of
	 * ready fds across the read/write/exception sets — fs/select.c::
	 * do_select() walks each bitmap of size nfds independently and sums
	 * set-bit counts across all three, so a single fd present in all
	 * three sets contributes 3 to the return.  The upper bound is
	 * therefore 3 * nfds, not nfds.  Failure returns -1UL with EBADF/
	 * EFAULT/EINTR/EINVAL/ENOMEM.  Anything > 3 * nfds (excluding -1UL)
	 * is a structural ABI regression: a sign-extension tear, a torn
	 * write of the count by a parallel signal-restart path, or -errno
	 * leaking through the success slot.
	 */
	if ((long) retval != -1L && retval > 3UL * snap->nfds) {
		outputerr("post_pselect6: rejected retval=0x%lx > 3*nfds=%u\n",
			  retval, 3 * snap->nfds);
		post_handler_corrupt_ptr_bump(rec, NULL);
		/* fall through to release the snap */
	}

	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_pselect6 = {
	.name = "pselect6",
	.num_args = 6,
	.flags = AVOID_SYSCALL, // Can cause the fuzzer to hang without timeout firing
	.argtype = { [0] = ARG_LEN, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS, [4] = ARG_ADDRESS, [5] = ARG_ADDRESS },
	.argname = { [0] = "n", [1] = "inp", [2] = "outp", [3] = "exp", [4] = "tsp", [5] = "sig" },
	.sanitise = sanitise_pselect6,
	.post = post_pselect6,
	.group = GROUP_VFS,
	.rettype = RET_BORING,
};
