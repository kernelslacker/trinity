/*
 * SYSCALL_DEFINE6(pselect6, int, n, fd_set __user *, inp, fd_set __user *, outp,
	fd_set __user *, exp, struct timespec __user *, tsp,
	void __user *, sig)
 */
#include <signal.h>
#include <string.h>
#include <time.h>

#include "fd.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * pselect6(2)'s arg6 sigset_argpack ss_len field: the kernel copies
 * the two-word struct then validates ss_len == _NSIG/8 (8 bytes) in
 * set_user_sigmask() before installing the mask.  Anything else short-
 * circuits to -EINVAL long before the mask copy, matching the sibling
 * style used by epoll_pwait / ppoll / rt_sigtimedwait / rt_sigaction.
 */
#define KERNEL_SIGSET_SIZE	8

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
	unsigned long *argpack;
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
		rec->a6 = 0;
		return;
	}

	FD_ZERO(rfds);
	FD_ZERO(wfds);
	FD_ZERO(exfds);

	nset = rnd_modulo_u32(10);
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
	ts = get_writable_address(sizeof(struct timespec));
	if (ts == NULL) {
		rec->a5 = 0;
	} else {
		ts->tv_sec = 0;
		ts->tv_nsec = 10000;
		rec->a5 = (unsigned long) ts;
		avoid_shared_buffer_inout(&rec->a5, sizeof(struct timespec));
	}

	/*
	 * arg6 is a pointer to a two-word sigset_argpack:
	 *   struct { const sigset_t *ss; size_t ss_len; }
	 * fs/select.c::do_pselect() calls get_sigset_argpack() to copy those
	 * two words, then set_user_sigmask() rejects any ss_len != _NSIG/8
	 * (== KERNEL_SIGSET_SIZE, 8 bytes) before touching the mask.  Passing
	 * a bare sigset_t pointer for arg6 makes the kernel misparse the raw
	 * mask bytes as (ptr, size) and kills the only code path that
	 * distinguishes pselect6 from pselect.  Build the argpack in the
	 * writable pool with a zeroed 8-byte mask; a 10% minority uses a
	 * deliberately-wrong ss_len to keep the EINVAL early-reject warm.
	 */
	argpack = get_writable_address(sizeof(unsigned long) * 2);
	sigmask = get_writable_address(KERNEL_SIGSET_SIZE);
	if (argpack == NULL || sigmask == NULL) {
		rec->a6 = 0;
	} else {
		memset(sigmask, 0, KERNEL_SIGSET_SIZE);
		argpack[0] = (unsigned long) sigmask;
		argpack[1] = (rnd_modulo_u32(10) == 0)
			? 0
			: KERNEL_SIGSET_SIZE;
		rec->a6 = (unsigned long) argpack;
		avoid_shared_buffer_inout(&rec->a6, sizeof(unsigned long) * 2);
	}

	/*
	 * Stash nfds for the post handler's retval bound check.  The snap
	 * itself is a small heap allocation (not a syscall-visible buffer)
	 * and carries a magic cookie; install it through the ownership
	 * table so the post handler can run post_state_claim_owned() and
	 * prove ownership before dereferencing any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = PSELECT6_POST_STATE_MAGIC;
	snap->nfds = nfds;
	post_state_install(rec, snap);
}

static void post_pselect6(struct syscallrecord *rec)
{
	struct pselect6_post_state *snap;
	unsigned long retval = rec->retval;

	rec->a2 = 0;
	rec->a3 = 0;
	rec->a4 = 0;
	rec->a5 = 0;
	rec->a6 = 0;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, PSELECT6_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

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

	post_state_release(rec, snap);
}

struct syscallentry syscall_pselect6 = {
	.name = "pselect6",
	.num_args = 6,
	.flags = AVOID_SYSCALL | NEED_ALARM, // Can cause the fuzzer to hang without timeout firing
	.argtype = { [0] = ARG_LEN, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS, [4] = ARG_ADDRESS, [5] = ARG_ADDRESS },
	.argname = { [0] = "n", [1] = "inp", [2] = "outp", [3] = "exp", [4] = "tsp", [5] = "sig" },
	.sanitise = sanitise_pselect6,
	.post = post_pselect6,
	.group = GROUP_VFS,
	.rettype = RET_BORING,
};
