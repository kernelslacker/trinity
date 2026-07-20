/*
 * sys_poll(struct pollfd __user *ufds, unsigned int nfds, int timeout);
 */
#include <signal.h>
#include <string.h>
#include <asm/poll.h>
#include "fd.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/poll.h"

/* Kernel sigset_t is a fixed 64-bit mask; sizeof matches on every arch. */
#define KERNEL_SIGSET_SIZE	8
static const unsigned long poll_events[] = {
	POLLIN, POLLPRI, POLLOUT, POLLERR,
	POLLHUP, POLLNVAL, POLLRDNORM, POLLRDBAND,
	POLLWRNORM, POLLWRBAND, POLLMSG, POLLREMOVE,
	POLLRDHUP, POLLFREE, POLL_BUSY_LOOP,
};

/*
 * Allocate and populate the pollfd[] array shared by both poll and ppoll,
 * stashing the array pointer and length in rec->a1/a2.  Returns the
 * pointer to the caller so each syscall can hand the original heap
 * allocation to the rec_own carrier (drained unconditionally after .post)
 * -- ppoll additionally captures its timespec into a post_state struct
 * snapshot for the oracle.
 */
static struct pollfd *alloc_pollfds(struct syscallrecord *rec)
{
	struct pollfd *pollfd;
	unsigned int i;
	unsigned int num_fds = rnd_modulo_u32(10);

	pollfd = zmalloc_tracked(num_fds * sizeof(struct pollfd));

	for (i = 0; i < num_fds; i++) {
		int fd = -1;
		unsigned int tries;

		/*
		 * Bias toward fds with a real wait queue — the kernel's
		 * wake/wait codepath through do_sys_poll → vfs_poll →
		 * fops->poll only blocks when the polled fd's fd_type has
		 * a backing waitqueue (pipe, eventfd, timerfd, signalfd,
		 * inotify, fanotify, socket).  Random fds drawn from
		 * get_random_fd() are dominated by regular-file fds
		 * (POLLIN | POLLOUT immediate return) and untracked /
		 * closed fds (POLLNVAL), neither of which exercises the
		 * wait-then-wake logic the audit doc references for poll.
		 *
		 * Distribution per slot:
		 *   ~60% pollable fd from a tracked fd_type / fd-event
		 *        provider via get_pollable_random_fd()
		 *   ~30% generic random fd (legacy long tail)
		 *   ~10% deliberately invalid fd to keep the POLLNVAL
		 *        rejection path warm
		 *
		 * Same blocking-poll wedge guard as arm_epoll(): poll(2)
		 * runs each pollfd's ->poll synchronously; a /dev/fuse
		 * handle without a live daemon parks the child in
		 * TASK_UNINTERRUPTIBLE on the FUSE waitqueue.  Reroll up
		 * to a bounded number of times; if we still hit a tagged
		 * fd, set the pollfd entry's fd to -1 so the kernel
		 * ignores it (do_sys_poll skips negative fds per the
		 * POLLNVAL guard).
		 */
		for (tries = 0; tries < 16; tries++) {
			unsigned int roll = rnd_modulo_u32(100);

			if (roll < 60) {
				fd = get_pollable_random_fd();
			} else if (roll < 90) {
				fd = get_random_fd();
			} else {
				/* invalid-fd bucket: a high fd number
				 * unlikely to be open, exercising the
				 * EBADF / POLLNVAL leg of do_sys_poll. */
				fd = (int) (8000 + rnd_modulo_u32(2000));
				break;
			}
			if (fd < 0)
				break;
			if (!fd_poll_can_block(fd))
				break;
			__atomic_add_fetch(&shm->stats.epoll_volatility.blocking_poll_skipped, 1,
					   __ATOMIC_RELAXED);
			fd = -1;
		}

		pollfd[i].fd = fd;
		pollfd[i].events = set_rand_bitmask(ARRAY_SIZE(poll_events), poll_events);
	}

	rec->a1 = (unsigned long) pollfd;
	rec->a2 = num_fds;
	return pollfd;
}

static void sanitise_poll(struct syscallrecord *rec)
{
	struct pollfd *pollfd = alloc_pollfds(rec);

	/*
	 * The kernel both reads pollfd[i].fd and pollfd[i].events from
	 * the caller and writes pollfd[i].revents back, so this is a
	 * value-result buffer.  alloc_pollfds() handed us a zmalloc()'d
	 * buffer that lives inside the libc brk arena, so a fuzzed ufds
	 * pointer (or even the legitimate one) lets the kernel scribble
	 * glibc chunk metadata.  Route the array through
	 * avoid_shared_buffer_inout() so the redirected allocation
	 * preserves the fd/events we just populated and the revents
	 * write lands in a known-safe writable region instead.
	 */
	avoid_shared_buffer_inout(&rec->a1, rec->a2 * sizeof(struct pollfd));

	/*
	 * Hand the original pollfd heap allocation to the rec carrier so the
	 * post-iteration drain frees it unconditionally.  Own the
	 * pre-relocation pointer (not rec->a1, which avoid_shared_buffer_inout
	 * may have redirected into the get_writable_address() pool); the drain
	 * runs after .post and closes the skip-.post leak (retfd-rejected /
	 * killed grandchild) that a guarded deferred_freeptr() would miss.
	 */
	rec_own(rec, pollfd);
}

static void post_poll(struct syscallrecord *rec)
{
	/*
	 * Read nfds via the arg_shadow accessor: the bound check below
	 * compares retval against the nfds the kernel actually saw.
	 * Reading live rec->a2 would let a sibling stomp landing between
	 * the syscall returning and this handler swing the bound -- a
	 * lowered nfds manufactures a false-positive corruption bump
	 * against a legitimate retval, and a raised nfds masks a real
	 * structural ABI regression.  arg_snapshot_mask on syscall_poll
	 * opts a2 (nfds) into the dispatch-time shadow captured in
	 * __do_syscall() after the final blanket_address_scrub;
	 * get_arg_snapshot() returns that value and bumps the
	 * arg_shadow_stomp tripwire from inside the accessor on mismatch.
	 */
	unsigned long nfds = get_arg_snapshot(rec, 2);
	unsigned long retval = rec->retval;

	/*
	 * Kernel ABI: poll(2) on success returns the count of fds with
	 * non-zero revents — a value in [0, nfds] computed by do_sys_poll()
	 * walking the user-supplied pollfd array. Failure returns -1UL with
	 * EFAULT/EINTR/EINVAL/ENOMEM via the syscall return path. Anything
	 * > nfds (excluding -1UL) is a structural ABI regression: a
	 * sign-extension tear, a torn write of the count, or -errno leaking
	 * through the success return slot.  The pollfd buffer is freed
	 * unconditionally by the rec_own drain after .post returns.
	 */
	if (retval != (unsigned long)-1L && retval > nfds) {
		outputerr("post_poll: retval %ld outside [0, %lu] and != -1UL\n",
			  (long) retval, nfds);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

struct syscallentry syscall_poll = {
	.name = "poll",
	.num_args = 3,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN, [2] = ARG_RANGE },
	.argname = { [0] = "ufds", [1] = "nfds", [2] = "timeout_msecs" },
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 100,
	.flags = NEED_ALARM,
	.sanitise = sanitise_poll,
	.post = post_poll,
	.group = GROUP_VFS,
	.rettype = RET_BORING,
	/* a2 (nfds) is the per-call retval bound the post-oracle compares
	 * rec->retval against.  Shadow it so a sibling stomp between
	 * dispatch and post cannot swing the bound -- mismatch bumps
	 * arg_shadow_stomp from inside get_arg_snapshot() and the handler
	 * still sees the nfds the kernel actually executed against. */
	.arg_snapshot_mask = (1u << 1),
};

/*
 * SYSCALL_DEFINE5(ppoll, struct pollfd __user *, ufds, unsigned int, nfds,
	 struct timespec __user *, tsp, const sigset_t __user *, sigmask, size_t, sigsetsize)
 */

/*
 * Snapshot of the two heap allocations sanitise hands to ppoll, captured
 * at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so the post
 * path is immune to a sibling syscall scribbling rec->a1/a3 between the
 * syscall returning and the post handler running.
 *
 * Wired into the post_state ownership table by post_state_install() at
 * sanitise time; post_ppoll() gates the snap through
 * post_state_claim_owned() before any field deref, so a sibling stomp
 * that redirects rec->post_state at a foreign heap chunk is rejected
 * by the ownership lookup before the leading-word magic compare ever
 * runs.  The bucket-pad keeps the 32-byte snap in its own glibc
 * free-list bucket as defense-in-depth on top of ownership + cookie.
 */
#define PPOLL_POST_STATE_MAGIC	0x50504F4C5F4D4147UL	/* "PPOL_MAG" */
struct ppoll_post_state {
	unsigned long magic;
	struct pollfd *fds;
	struct timespec *ts;
	unsigned long _bucket_pad;
};

static void sanitise_ppoll(struct syscallrecord *rec)
{
	struct ppoll_post_state *snap;
	struct pollfd *fds;
	struct timespec *ts;
	sigset_t *mask;

	/* Clear post_state up front so the early-return path below cannot
	 * leave stale data from a previous syscall in the slot. */
	rec->post_state = 0;

	fds = alloc_pollfds(rec);
	if (fds == NULL)
		return;

	ts = zmalloc_tracked(sizeof(struct timespec));
	rec->a3 = (unsigned long) ts;
	ts->tv_sec = 1;
	ts->tv_nsec = 0;

	/*
	 * ppoll's set_user_sigmask requires sigsetsize == KERNEL_SIGSET_SIZE
	 * (8 bytes; _NSIG/8) and rejects anything else with -EINVAL.
	 * Userspace sizeof(sigset_t) is 128 on glibc, so passing that as a5
	 * always short-circuited the mask arm before the kernel touched a4 --
	 * the mask-install path was dead coverage.  Point a4 at a zeroed
	 * 8-byte pool buffer (a raw ARG_ADDRESS would EFAULT the small
	 * copy_from_user) and pass KERNEL_SIGSET_SIZE as sigsetsize.  A 10%
	 * NULL-mask arm keeps the "no mask install" leg warm; a 10% bad-size
	 * arm keeps the -EINVAL gate exercised.
	 */
	mask = (sigset_t *) get_writable_struct(KERNEL_SIGSET_SIZE);
	if (mask != NULL)
		memset(mask, 0, KERNEL_SIGSET_SIZE);
	rec->a4 = (unsigned long) mask;
	rec->a5 = KERNEL_SIGSET_SIZE;

	if (rnd_modulo_u32(10) == 0)
		rec->a4 = 0;
	else if (rnd_modulo_u32(10) == 0)
		rec->a5 = sizeof(sigset_t);

	/*
	 * ppoll(2) reads pollfd[i].fd/events and writes pollfd[i].revents
	 * back; tsp is also value-result (kernel reads the requested
	 * timeout and rewrites it with the remaining time when a signal
	 * interrupts the wait).  Both buffers come from zmalloc(), i.e.
	 * the libc brk arena, so the kernel writes can land on top of
	 * glibc chunk metadata.  Route both through
	 * avoid_shared_buffer_inout() so the initial fd/events/timeout
	 * values survive the relocation and the kernel's writeback hits
	 * a known-safe writable region when the original ranges overlap
	 * the libc heap or any tracked shared region.
	 */
	avoid_shared_buffer_inout(&rec->a1, rec->a2 * sizeof(struct pollfd));
	avoid_shared_buffer_inout(&rec->a3, sizeof(struct timespec));

	/*
	 * Snapshot both heap pointers for the post handler.  rec->a1 and
	 * rec->a3 can be scribbled by a sibling syscall between the syscall
	 * returning and the post handler running, leaving real-but-wrong
	 * heap pointers that looks_like_corrupted_ptr() cannot distinguish
	 * from the originals.  Capture the original fds/ts allocations (not
	 * the post-relocation rec->a1/a3) -- post_ppoll() frees them via
	 * deferred_free_enqueue(), and the relocated addresses live in the
	 * get_writable_address() pool, not the glibc heap.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = PPOLL_POST_STATE_MAGIC;
	snap->fds = fds;
	snap->ts = ts;
	post_state_install(rec, snap);

	/*
	 * Hand the fds/timespec heap allocations to the rec carrier so the
	 * post-iteration drain frees them unconditionally.  The .post handler
	 * still reads via snap->fds / snap->ts (drain runs after .post), and
	 * the carrier closes the leak on the skip-.post paths
	 * (retfd-rejected, child killed) that deferred_free_enqueue() inside
	 * .post would miss.
	 */
	rec_own(rec, fds);
	rec_own(rec, ts);
}

static void post_ppoll(struct syscallrecord *rec)
{
	struct ppoll_post_state *snap;
	/*
	 * Read nfds via the arg_shadow accessor (mirrors post_poll above):
	 * the bound check below compares retval against the nfds the
	 * kernel actually saw, so a sibling stomp of rec->a2 between
	 * dispatch and post must not be allowed to swing the bound and
	 * either fabricate or hide a corruption signal.  The ppoll
	 * post_state snap deliberately does not carry nfds -- the generic
	 * arg_shadow path defends a2 directly and bumps arg_shadow_stomp
	 * from inside get_arg_snapshot() on mismatch, so a separate
	 * snap->nfds field would duplicate the defense.
	 */
	unsigned long nfds = get_arg_snapshot(rec, 2);
	unsigned long retval = rec->retval;

	/*
	 * Kernel ABI: ppoll(2) on success returns the count of fds with
	 * non-zero revents — a value in [0, nfds] from do_sys_poll(), the
	 * shared inner routine. Failure returns -1UL with
	 * EFAULT/EINTR/EINVAL/ENOMEM. Anything > nfds (excluding -1UL) is a
	 * structural ABI regression matching the poll(2) shape: a
	 * sign-extension tear, a torn write of the count by a parallel
	 * signal-restart path, or -errno leaking through the success slot.
	 * Validate before the snapshot teardown so the corruption is caught
	 * even when snap is NULL or scribbled; the existing snap cleanup
	 * still runs against any retval shape so the heap allocations are
	 * freed either way.
	 */
	if (retval != (unsigned long)-1L && retval > nfds) {
		outputerr("post_ppoll: retval %ld outside [0, %lu] and != -1UL\n",
			  (long) retval, nfds);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

	rec->a1 = 0;
	rec->a3 = 0;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, PPOLL_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, snap->fds) ||
	    looks_like_corrupted_ptr(rec, snap->ts)) {
		outputerr("post_ppoll: rejected suspicious snap fds=%p ts=%p "
			  "(post_state-scribbled?)\n", snap->fds, snap->ts);
		post_state_release(rec, snap);
		return;
	}

	post_state_release(rec, snap);
}

struct syscallentry syscall_ppoll = {
	.name = "ppoll",
	.num_args = 5,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS, [4] = ARG_LEN },
	.argname = { [0] = "ufds", [1] = "nfds", [2] = "tsp", [3] = "sigmask", [4] = "sigsetsize" },
	.flags = NEED_ALARM,
	.sanitise = sanitise_ppoll,
	.post = post_ppoll,
	.group = GROUP_VFS,
	.rettype = RET_BORING,
	/* Mirror syscall_poll: shadow a2 (nfds) so the post-oracle's
	 * retval-vs-nfds bound reads the kernel-visible value via
	 * get_arg_snapshot() instead of the sibling-stomp-vulnerable
	 * rec->a2 slot.  The post_state snap defends the heap pointers
	 * (fds/ts); arg_shadow defends the bound. */
	.arg_snapshot_mask = (1u << 1),
};
