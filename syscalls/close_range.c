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
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>
#include "child.h"
#include "deferred-free.h"
#include "fd-event.h"
#include "kcov.h"
#include "objects.h"
#include "pids.h"
#include "random.h"
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
 * The scribble-class here is the same one many recent post handlers
 * have been hardened against; treat it the same way.
 */
#define CLOSE_RANGE_POST_STATE_MAGIC	0x43524E474D41475FUL	/* "CRNGMAG_" */
struct close_range_post_state {
	unsigned long magic;
	unsigned int fd;
	unsigned int max_fd;
	unsigned int flags;
};

/*
 * Per-child disposable high-fd sandbox: dup /dev/null into a
 * contiguous block of fds well above the trinity-tracked pool
 * (NR_FILE_FDS == 250) so close_range() can run for real against
 * targets the rest of the fuzzer doesn't care about.  Without this
 * the syscall sat behind AVOID_SYSCALL because every ARG_FD-derived
 * range risked closing live trinity-tracked fds.
 *
 * State is __thread so each forked child gets its own slots without
 * coordination.  Slots are populated lazily on the first sanitise
 * call and never refilled; once a child burns through the range
 * with non-CLOEXEC closes the sandbox-internal buckets fall through
 * to the ARG_FD-derived branches and the syscall still gets shaped.
 */
#define CLOSE_RANGE_SANDBOX_BASE	2048

static __thread bool sandbox_init;
static __thread int  sandbox_base;
static __thread int  sandbox_n;

static void close_range_init_sandbox(void)
{
	int devnull, base = CLOSE_RANGE_SANDBOX_BASE;
	int n = (int) RAND_RANGE(16, 64);
	int i, dupped = 0;

	sandbox_init = true;
	sandbox_base = 0;
	sandbox_n    = 0;

	devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
	if (devnull < 0)
		return;

	for (i = 0; i < n; i++) {
		int slot = base + i;

		/* Skip if the slot is already occupied -- inherited
		 * fds from the parent or environment must not be
		 * clobbered.  Stop at the first occupied slot so the
		 * sandbox range stays contiguous. */
		if (fcntl(slot, F_GETFD) != -1 || errno != EBADF)
			break;

		if (dup2(devnull, slot) != slot) {
			/* EMFILE / ENFILE / EINTR -- accept whatever
			 * we managed to populate and fall through
			 * gracefully rather than abort the sanitise. */
			break;
		}
		dupped++;
	}
	close(devnull);

	if (dupped > 0) {
		sandbox_base = base;
		sandbox_n    = dupped;
	}
}

static void sanitise_close_range(struct syscallrecord *rec)
{
	struct close_range_post_state *snap;
	bool sandbox_ok;
	unsigned int pick;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	if (!sandbox_init)
		close_range_init_sandbox();
	sandbox_ok = (sandbox_n > 0);

	/*
	 * Bucketed range picker.  Roughly 50% of calls target the
	 * disposable sandbox so the kernel sees real close walks on
	 * fds trinity doesn't care about; the remaining 50% start
	 * from the ARG_FD-derived range and twist it through inverted,
	 * CLOEXEC-marking, and unshare-with-harmless-close shapes.
	 */
	pick = rnd_modulo_u32(100);

	if (sandbox_ok && pick < 50) {
		/* Sandbox-internal close, mixed shapes. */
		unsigned int shape = rnd_modulo_u32(4);
		int base = sandbox_base;
		int top  = sandbox_base + sandbox_n - 1;
		int lo, hi;

		switch (shape) {
		case 0:	/* single-fd close */
			lo = base + (int) rnd_modulo_u32((uint32_t) sandbox_n);
			hi = lo;
			break;
		case 1:	/* adjacent pair (hi == lo + 1) */
			if (sandbox_n >= 2) {
				lo = base + (int) rnd_modulo_u32(
					(uint32_t) (sandbox_n - 1));
				hi = lo + 1;
			} else {
				lo = base;
				hi = base;
			}
			break;
		case 2:	/* full sandbox span */
			lo = base;
			hi = top;
			break;
		default: { /* sub-range */
			int a = base + (int) rnd_modulo_u32((uint32_t) sandbox_n);
			int b = base + (int) rnd_modulo_u32((uint32_t) sandbox_n);
			if (a <= b) { lo = a; hi = b; }
			else        { lo = b; hi = a; }
			break;
		}
		}
		rec->a1 = (unsigned long) lo;
		rec->a2 = (unsigned long) hi;
	} else if (pick < 65) {
		/* Reversed ARG_FD range: hi < lo.  The kernel should
		 * reject with EINVAL; exercises the post handler's
		 * `max_fd < fd` snapshot guard against underflow. */
		unsigned long tmp = rec->a1;
		rec->a1 = rec->a2;
		rec->a2 = tmp;
	} else if (pick < 80) {
		/* CLOEXEC-only marking on a range sitting just above
		 * a protected kcov fd.  CLOEXEC doesn't close, so this
		 * is safe even though the range is adjacent to fds the
		 * fuzzer must not lose. */
		struct childdata *c = this_child();

		if (c != NULL && c->kcov.fd >= 0) {
			rec->a1 = (unsigned long) (c->kcov.fd + 1);
			rec->a2 = (unsigned long) (c->kcov.fd + 2);
		}
		rec->a3 = CLOSE_RANGE_CLOEXEC;
	} else if (sandbox_ok && pick < 90) {
		/* CLOSE_RANGE_UNSHARE combined with a sandbox-internal
		 * range: the unshare side effect on the fd table runs
		 * but the actual close lands on disposable slots. */
		int base = sandbox_base;
		int span = (int) rnd_modulo_u32((uint32_t) sandbox_n);

		rec->a1 = (unsigned long) base;
		rec->a2 = (unsigned long) (base + span);
		rec->a3 = CLOSE_RANGE_UNSHARE;
	}
	/* else: leave the ARG_FD-derived range and the ARG_LIST flags
	 * untouched -- the original behaviour. */

	/*
	 * If the picked range sweeps over one of this child's kcov fds,
	 * truncate the upper bound so the kernel never sees the protected
	 * slot.  Bounds were picked by gen_arg_fd (which already filters
	 * protected fds), so the endpoints themselves are safe -- it is the
	 * range walk in between that needs the guard.  CLOEXEC-only calls
	 * just mark fds, but doing the truncation unconditionally keeps the
	 * snapshot the post handler reads consistent with the kernel's view
	 * regardless of the flags bit.  If the truncation leaves no fds to
	 * close (lowest protected fd <= rec->a1) we collapse the range to
	 * a no-op (close_range(N, N - 1) returns -EINVAL) rather than
	 * issuing a side-effect-free syscall on an unrelated low slot.
	 */
	if (rec->a1 <= rec->a2 &&
	    kcov_range_contains_protected_fd((int) rec->a1, (int) rec->a2)) {
		struct childdata *c = this_child();
		unsigned int new_max = (unsigned int) rec->a2;

		if (c != NULL) {
			if (c->kcov.fd >= 0 &&
			    (unsigned int) c->kcov.fd <= new_max &&
			    (unsigned int) c->kcov.fd >= (unsigned int) rec->a1)
				new_max = (unsigned int) c->kcov.fd - 1U;
			if (c->kcov.cmp_fd >= 0 &&
			    (unsigned int) c->kcov.cmp_fd <= new_max &&
			    (unsigned int) c->kcov.cmp_fd >= (unsigned int) rec->a1)
				new_max = (unsigned int) c->kcov.cmp_fd - 1U;
		}
		if (new_max < (unsigned int) rec->a1) {
			/* Whole range was at or above the lowest protected fd
			 * -- nothing left to close.  Invert the bounds so the
			 * kernel rejects the call instead of issuing a walk. */
			rec->a2 = rec->a1 > 0 ? rec->a1 - 1UL : 0UL;
		} else {
			rec->a2 = new_max;
		}
	}

	snap = zmalloc_tracked(sizeof(*snap));
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
	 * Trinity routinely fuzzes this syscall with negative values.
	 * snap->fd stores the unsigned bit pattern of the original a1,
	 * so a well-formed range of negatives (max_fd just above fd as
	 * signed ints) glides through the 1024-fd clamp below and ends
	 * up enqueueing FD_EVENT_CLOSE events that cast back to negative
	 * fds.  The parent ring rejects them via payload_valid(), but
	 * each rejection is logged, so a single fuzz call can spam ~1k
	 * corrupt-event messages.  Bail -- the parent has nothing to do
	 * with negative fds anyway.
	 */
	if ((int) fd < 0)
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
					 (int) fd);

		/* Drop the just-closed fd from this child's own fd_hash[]
		 * snapshot so get_random_fd() / get_typed_fd() stop handing
		 * it back out before the parent drains the FD_EVENT_CLOSE. */
		fd_hash_remove_local((int) fd);

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
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
