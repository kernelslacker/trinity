/*
 * SYSCALL_DEFINE6(pselect6, int, n, fd_set __user *, inp, fd_set __user *, outp,
	fd_set __user *, exp, struct timespec __user *, tsp,
	void __user *, sig)
 */
#include <sys/time.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
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
 * Snapshot of the five heap allocations sanitise hands to the kernel,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so the post
 * path is immune to a sibling syscall scribbling rec->a2/a3/a4/a5/a6
 * between the syscall returning and the post handler running.
 */
#define PSELECT6_POST_STATE_MAGIC	0x50534C36UL	/* "PSL6" */
struct pselect6_post_state {
	unsigned long magic;
	fd_set *rfds;
	fd_set *wfds;
	fd_set *exfds;
	struct timespec *ts;
	sigset_t *sigmask;
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

	rfds = zmalloc_tracked(sizeof(fd_set));
	wfds = zmalloc_tracked(sizeof(fd_set));
	exfds = zmalloc_tracked(sizeof(fd_set));

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

	/* Set a really short timeout */
	ts = zmalloc_tracked(sizeof(struct timespec));
	ts->tv_sec = 0;
	ts->tv_nsec = 10000;
	rec->a5 = (unsigned long) ts;

	/*
	 * Hand the kernel a real (zeroed) sigmask buffer rather than NULL so
	 * the copy_from_user path on the kernel side still has something to
	 * read.  An empty mask is semantically equivalent to NULL for the
	 * purposes of pselect6's signal-blocking dance, but keeps the buffer
	 * exercised by the SHM-output scrub below.
	 */
	sigmask = zmalloc_tracked(sizeof(sigset_t));
	rec->a6 = (unsigned long) sigmask;

	/*
	 * Relocate any buffers that landed in the shared SHM region or
	 * the libc brk arena before the snapshot is taken — the snapshot
	 * must reference the post-relocation pointers, not the original
	 * heap addresses, so the post handler frees what the kernel
	 * actually wrote to.
	 *
	 * All five buffers must be _inout: the three fd_sets are
	 * value-result (kernel reads the requested-bit mask we populated
	 * via FD_SET() and writes back the ready-bit mask), the timespec
	 * carries the requested timeout (tv_sec/tv_nsec we just stored)
	 * and is also written back with the remaining time on signal,
	 * and the sigmask carries the bits the kernel installs around
	 * the wait.  avoid_shared_buffer_out() would zero the relocated
	 * allocation, defeating every FD_SET above and turning the short
	 * 10us timeout into an indefinite wait.
	 */
	avoid_shared_buffer_inout(&rec->a2, sizeof(fd_set));
	avoid_shared_buffer_inout(&rec->a3, sizeof(fd_set));
	avoid_shared_buffer_inout(&rec->a4, sizeof(fd_set));
	avoid_shared_buffer_inout(&rec->a5, sizeof(struct timespec));
	avoid_shared_buffer_inout(&rec->a6, sizeof(sigset_t));

	/*
	 * Snapshot all five heap pointers for the post handler.  A sibling
	 * syscall can scribble rec->a2/a3/a4/a5/a6 between the syscall
	 * returning and the post handler running, leaving real-but-wrong
	 * heap pointers that looks_like_corrupted_ptr() cannot distinguish
	 * from the originals; the post handler then hands the wrong
	 * allocations to free, leaking ours and corrupting another sanitise
	 * routine's live buffers.  rec->post_state is private to the post
	 * handler, so the scribblers have nothing to scribble there.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = PSELECT6_POST_STATE_MAGIC;
	snap->rfds = (fd_set *) rec->a2;
	snap->wfds = (fd_set *) rec->a3;
	snap->exfds = (fd_set *) rec->a4;
	snap->ts = (struct timespec *) rec->a5;
	snap->sigmask = (sigset_t *) rec->a6;
	snap->nfds = nfds;
	rec->post_state = (unsigned long) snap;
}

static void post_pselect6(struct syscallrecord *rec)
{
	struct pselect6_post_state *snap = (struct pselect6_post_state *) rec->post_state;

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
	 * leaking through the success slot.  Validate before the inner-
	 * pointer guards so the corruption is caught even when the inner
	 * pointers are scribbled; fall through to the existing teardown so
	 * the heap allocations are still released.
	 */
	if ((long) rec->retval != -1L && rec->retval > 3UL * snap->nfds) {
		outputerr("post_pselect6: rejected retval=0x%lx > 3*nfds=%u\n",
			  rec->retval, 3 * snap->nfds);
		post_handler_corrupt_ptr_bump(rec, NULL);
		/* fall through to existing teardown to release deferred allocations */
	}

	/*
	 * Defense in depth: if something corrupted the snapshot itself,
	 * the inner pointers may no longer reference our heap allocations.
	 * Leak rather than hand garbage to free().
	 */
	if (looks_like_corrupted_ptr(rec, snap->rfds) ||
	    looks_like_corrupted_ptr(rec, snap->wfds) ||
	    looks_like_corrupted_ptr(rec, snap->exfds) ||
	    looks_like_corrupted_ptr(rec, snap->ts) ||
	    looks_like_corrupted_ptr(rec, snap->sigmask)) {
		outputerr("post_pselect6: rejected suspicious snap rfds=%p wfds=%p "
			  "exfds=%p ts=%p sigmask=%p (post_state-scribbled?)\n",
			  snap->rfds, snap->wfds, snap->exfds, snap->ts, snap->sigmask);
		deferred_freeptr(&rec->post_state);
		return;
	}

	deferred_free_enqueue(snap->rfds);
	deferred_free_enqueue(snap->wfds);
	deferred_free_enqueue(snap->exfds);
	deferred_free_enqueue(snap->ts);
	deferred_free_enqueue(snap->sigmask);
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
