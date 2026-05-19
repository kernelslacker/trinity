/**
 * close_range() - Close all file descriptors in a given range.
 *
 * @fd:     starting file descriptor to close
 * @max_fd: last file descriptor to close
 * @flags:  reserved for future extensions
 *
 * This closes a range of file descriptors. All file descriptors
 * from @fd up to and including @max_fd are closed.
 * Currently, errors to close a given file descriptor are ignored.
 */
#include "child.h"
#include "deferred-free.h"
#include "fd-event.h"
#include "objects.h"
#include "pids.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

#define CLOSE_RANGE_UNSHARE     (1U << 1)
#define CLOSE_RANGE_CLOEXEC     (1U << 2)

static unsigned long close_range_flags[] = {
	CLOSE_RANGE_UNSHARE, CLOSE_RANGE_CLOEXEC,
};

/*
 * Snapshot of the three input args, captured at sanitise time and
 * consumed by the post handler.  Lives in rec->post_state, a slot the
 * syscall ABI does not expose, so a sibling syscall scribbling
 * rec->a1/a2/a3 between the syscall returning and the post handler
 * running cannot mis-direct the post-side fd-event enqueue.
 *
 * Without this snapshot the post handler reads rec->aN directly, which
 * lets two distinct stomps slip past:
 *
 *   1. A sibling raises rec->a2 (max_fd) far above the original close
 *      range, causing the FD_EVENT_CLOSE loop to enqueue spurious close
 *      events for fds the kernel never touched -- the parent's object
 *      pool then loses live fds.
 *   2. A sibling makes max_fd < fd between syscall return and post
 *      entry.  The unsigned `max_fd - fd > 1024` comparison underflows
 *      to a huge value, the clamp kicks in setting max_fd = fd + 1024,
 *      and the loop runs across 1025 fds that were never in the
 *      original syscall's range.
 *
 * close_range is AVOID_SYSCALL today so the in-tree exposure is
 * limited, but the scribble-class is the same one many recent post
 * handlers have been hardened against; treat it the same way.
 */
#define CLOSE_RANGE_POST_STATE_MAGIC	0x43524E474D41475FUL	/* "CRNGMAG_" */
struct close_range_post_state {
	unsigned long magic;
	unsigned int fd;
	unsigned int max_fd;
	unsigned int flags;
};

static void sanitise_close_range(struct syscallrecord *rec)
{
	struct close_range_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	snap = zmalloc(sizeof(*snap));
	snap->magic  = CLOSE_RANGE_POST_STATE_MAGIC;
	snap->fd     = (unsigned int) rec->a1;
	snap->max_fd = (unsigned int) rec->a2;
	snap->flags  = (unsigned int) rec->a3;
	rec->post_state = (unsigned long) snap;
}

/*
 * If close_range succeeded without CLOEXEC flag, the fds in the range
 * are actually closed.  Enqueue CLOSE events for each fd so the parent
 * can update the object pool.
 *
 * The fd/max_fd/flags values are read from the post_state snapshot so
 * a sibling scribbling rec->aN between syscall return and post entry
 * cannot mis-direct the close-event enqueue or trigger the unsigned
 * `max_fd - fd` underflow described above the post_state struct.
 */
static void post_close_range(struct syscallrecord *rec)
{
	struct close_range_post_state *snap =
		(struct close_range_post_state *) rec->post_state;
	struct childdata *child;
	unsigned int fd, max_fd, flags;

	if (rec->retval != 0)
		return;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_close_range: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as a
	 * close_range_post_state.  A cookie mismatch means snap does not
	 * point at our struct -- abandon rather than feed wild bytes into
	 * the fd-range walk.
	 */
	if (snap->magic != CLOSE_RANGE_POST_STATE_MAGIC) {
		outputerr("post_close_range: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return;
	}

	fd     = snap->fd;
	max_fd = snap->max_fd;
	flags  = snap->flags;

	/* CLOEXEC just marks fds, doesn't close them yet */
	if (flags & CLOSE_RANGE_CLOEXEC)
		goto out_free;

	/*
	 * Guard the unsigned subtraction below.  A snapshot with
	 * max_fd < fd is either a kernel that accepted an inverted range
	 * (it should not) or a snapshot whose inner fields were
	 * wholesale-stomped after the magic check; either way, skip the
	 * range walk rather than underflow `max_fd - fd` into a huge
	 * value that the 1024 clamp then turns into a 1025-fd walk
	 * starting at a fd the original syscall never touched.
	 */
	if (max_fd < fd)
		goto out_free;

	/* Sanity: don't scan billions of fds */
	if (max_fd - fd > 1024)
		max_fd = fd + 1024;

	child = this_child();

	/* One-pass purge of the live-fd ring for the whole range so we don't
	 * walk the 16-slot ring fd-by-fd inside the loop below. */
	if (child != NULL)
		child_fd_ring_remove_range(&child->live_fds,
					   (int) fd, (int) max_fd);

	for (; fd <= max_fd; fd++) {
		if (child != NULL && child->fd_event_ring != NULL)
			fd_event_enqueue(child->fd_event_ring, FD_EVENT_CLOSE,
					 (int) fd, -1, 0, 0, 0);

		/* Parent-side path (no-op in children). */
		remove_object_by_fd((int) fd);
	}

out_free:
	deferred_free_enqueue(snap);
	rec->post_state = 0;
}

struct syscallentry syscall_close_range = {
	.name = "close_range",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_FD, [2] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "max_fd", [2] = "flags" },
	.arg_params[2].list = ARGLIST(close_range_flags),
	.sanitise = sanitise_close_range,
	.post = post_close_range,
	.flags = AVOID_SYSCALL,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
