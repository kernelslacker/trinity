/*
 * sys_poll(struct pollfd __user *ufds, unsigned int nfds, int timeout);
 */
#include <stdlib.h>
#include <signal.h>
#include <asm/poll.h>
#include "fd.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

static const unsigned long poll_events[] = {
	POLLIN, POLLPRI, POLLOUT, POLLERR,
	POLLHUP, POLLNVAL, POLLRDBAND, POLLWRNORM,
	POLLWRBAND, POLLMSG, POLLREMOVE, POLLRDHUP,
	POLLFREE, POLL_BUSY_LOOP,
};

/*
 * Allocate and populate the pollfd[] array shared by both poll and ppoll,
 * stashing the array pointer and length in rec->a1/a2.  Returns the
 * pointer to the caller so each syscall can install its own post_state
 * snapshot (poll snapshots a single pointer; ppoll wraps both pollfd and
 * the timespec into a struct snapshot).
 */
static struct pollfd *alloc_pollfds(struct syscallrecord *rec)
{
	struct pollfd *pollfd;
	unsigned int i;
	unsigned int num_fds = rand() % 10;

	pollfd = zmalloc(num_fds * sizeof(struct pollfd));

	for (i = 0; i < num_fds; i++) {
		pollfd[i].fd = get_random_fd();
		pollfd[i].events = set_rand_bitmask(ARRAY_SIZE(poll_events), poll_events);
	}

	rec->a1 = (unsigned long) pollfd;
	rec->a2 = num_fds;
	return pollfd;
}

static void sanitise_poll(struct syscallrecord *rec)
{
	struct pollfd *pollfd = alloc_pollfds(rec);

	/* Snapshot for the post handler -- a1 may be scribbled by a sibling
	 * syscall before post_poll() runs. */
	rec->post_state = (unsigned long) pollfd;
}

static void post_poll(struct syscallrecord *rec)
{
	void *ufds = (void *) rec->post_state;
	unsigned long nfds = rec->a2;

	/*
	 * Kernel ABI: poll(2) on success returns the count of fds with
	 * non-zero revents — a value in [0, nfds] computed by do_sys_poll()
	 * walking the user-supplied pollfd array. Failure returns -1UL with
	 * EFAULT/EINTR/EINVAL/ENOMEM via the syscall return path. Anything
	 * > nfds (excluding -1UL) is a structural ABI regression: a
	 * sign-extension tear, a torn write of the count, or -errno leaking
	 * through the success return slot. Validate before the snapshot
	 * teardown so the corruption is caught even when the post_state
	 * pointer is NULL or scribbled; fall through to the existing free
	 * path so the heap allocation is still released.
	 */
	if (rec->retval != (unsigned long)-1L && rec->retval > nfds) {
		outputerr("post_poll: retval %ld outside [0, %lu] and != -1UL\n",
			  (long) rec->retval, nfds);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

	if (ufds == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, ufds)) {
		outputerr("post_poll: rejected suspicious ufds=%p (pid-scribbled?)\n", ufds);
		rec->a1 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a1 = 0;
	deferred_freeptr(&rec->post_state);
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
 */
struct ppoll_post_state {
	struct pollfd *fds;
	struct timespec *ts;
};

static void sanitise_ppoll(struct syscallrecord *rec)
{
	struct ppoll_post_state *snap;
	struct pollfd *fds;
	struct timespec *ts;

	/* Clear post_state up front so the early-return path below cannot
	 * leave stale data from a previous syscall in the slot. */
	rec->post_state = 0;

	fds = alloc_pollfds(rec);
	if (fds == NULL)
		return;

	ts = zmalloc(sizeof(struct timespec));
	rec->a3 = (unsigned long) ts;
	ts->tv_sec = 1;
	ts->tv_nsec = 0;

	rec->a5 = sizeof(sigset_t);

	/*
	 * Snapshot both heap pointers for the post handler.  rec->a1 and
	 * rec->a3 can be scribbled by a sibling syscall between the syscall
	 * returning and the post handler running, leaving real-but-wrong
	 * heap pointers that looks_like_corrupted_ptr() cannot distinguish
	 * from the originals.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->fds = fds;
	snap->ts = ts;
	rec->post_state = (unsigned long) snap;
}

static void post_ppoll(struct syscallrecord *rec)
{
	struct ppoll_post_state *snap = (struct ppoll_post_state *) rec->post_state;
	unsigned long nfds = rec->a2;

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
	if (rec->retval != (unsigned long)-1L && rec->retval > nfds) {
		outputerr("post_ppoll: retval %ld outside [0, %lu] and != -1UL\n",
			  (long) rec->retval, nfds);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

	rec->a1 = 0;
	rec->a3 = 0;

	if (snap == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_ppoll: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->post_state = 0;
		return;
	}

	if (looks_like_corrupted_ptr(rec, snap->fds) ||
	    looks_like_corrupted_ptr(rec, snap->ts)) {
		outputerr("post_ppoll: rejected suspicious snap fds=%p ts=%p "
			  "(post_state-scribbled?)\n", snap->fds, snap->ts);
		deferred_freeptr(&rec->post_state);
		return;
	}

	deferred_free_enqueue(snap->fds, NULL);
	deferred_free_enqueue(snap->ts, NULL);
	deferred_freeptr(&rec->post_state);
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
};
