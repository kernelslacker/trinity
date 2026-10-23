/*
 * SYSCALL_DEFINE3(close_range, unsigned int, fd, unsigned int, max_fd,
 *                 unsigned int, flags)
 *
 * Closes [fd, max_fd] (EXCEPT: all outside it; CLOEXEC_ONLY: only fds that
 * are close-on-exec).  No protected fd may be in the set the kernel closes:
 * the sanitiser narrows or widens the range, and validate_arg_coupling()
 * refuses a call rewritten after sanitise.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <unistd.h>
#include "child.h"
#include "fd.h"
#include "fd-event.h"
#include "kcov.h"
#include "objects.h"
#include "pids.h"
#include "random.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
#define CLOSE_RANGE_UNSHARE     (1U << 1)
#define CLOSE_RANGE_CLOEXEC     (1U << 2)

/* A kernel header that has these spells each as an enumerator plus a
 * macro of the same name, which an unguarded define here would redefine. */
#ifndef CLOSE_RANGE_EXCEPT
#define CLOSE_RANGE_EXCEPT	(1U << 3)
#endif
#ifndef CLOSE_RANGE_CLOEXEC_ONLY
#define CLOSE_RANGE_CLOEXEC_ONLY	(1U << 4)
#endif

static unsigned long close_range_flags[] = {
	CLOSE_RANGE_UNSHARE, CLOSE_RANGE_CLOEXEC,
	CLOSE_RANGE_EXCEPT, CLOSE_RANGE_CLOEXEC_ONLY,
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
 *      range, so the post handler reports a close of fds the kernel
 *      never touched -- this child's fd snapshots then lose live fds.
 *   2. A sibling makes max_fd < fd between syscall return and post
 *      entry.  The unsigned `max_fd - fd > 1024` comparison underflows
 *      to a huge value, the clamp kicks in setting max_fd = fd + 1024,
 *      and the post reports a close of 1025 fds that were never in the
 *      original syscall's range.
 *
 * The scribble-class here is the same one many recent post handlers
 * have been hardened against; treat it the same way.
 *
 * It is also the record of what the protected-fd guard vetted:
 * vet_final_close_range() holds the slots the kernel is about to read
 * to it.
 */
#define CLOSE_RANGE_POST_STATE_MAGIC	0x43524E474D41475FUL	/* "CRNGMAG_" */
struct close_range_post_state {
	unsigned long magic;
	unsigned int fd;
	unsigned int max_fd;
	unsigned int flags;
};

/*
 * The guard on the range runs in sanitise, but chain substitution
 * rewrites one slot after it, and all three take a number: an 8 in the
 * flags is EXCEPT, which closes everything outside the range, and a pid
 * or a byte count in max_fd runs the range back over the fds parked above
 * PROTECTED_FD_HIGH_BASE.  The post handler trusts the snapshot, so a
 * rewritten call would also be retired and reported as a range the
 * kernel never closed.  A call whose slots are not the ones that were
 * vetted is refused rather than repaired: a substituted close_range is
 * not worth a second pass of the guard.
 *
 * A record with no snapshot of ours has nothing to vouch for its range,
 * and one wasted call costs less than a closed kcov fd, so it fails too.
 * Shape, then ownership, then magic, as post_state_claim_owned() orders
 * them: the first two keep the read of the third safe.
 */
static int vet_final_close_range(struct syscallrecord *rec)
{
	const struct close_range_post_state *snap =
		(const struct close_range_post_state *) rec->post_state;

	if (is_corrupt_ptr_shape(snap) || !post_state_is_owned(snap) ||
	    snap->magic != CLOSE_RANGE_POST_STATE_MAGIC)
		goto refuse;

	/* The kernel reads each slot as an unsigned int. */
	if ((unsigned int) rec->a1 == snap->fd &&
	    (unsigned int) rec->a2 == snap->max_fd &&
	    (unsigned int) rec->a3 == snap->flags)
		return 0;

refuse:
	outputerr("arg-coupling: %s rejected: the slots are not the range sanitise vetted\n",
		  rec->entry->name);
	return -1;
}

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

/*
 * Keep the fds trinity depends on (kcov PC/cmp, STDERR_FILENO, the stderr
 * capture memfd) out of what the kernel is about to close.  Returns
 * whether the range had to change.
 *
 * Bounds were picked by gen_arg_fd (which already filters protected fds),
 * so the endpoints themselves are safe -- it is the walk in between, or
 * with EXCEPT the walk outside them, that needs the guard.
 *
 * Compare and pass bounds as unsigned int: the kernel's close_range ABI
 * takes (unsigned int first, unsigned int last), and gen_arg_fd's
 * exhaustion fallback hands back (unsigned long)-1, which the kernel sees
 * as 0xFFFFFFFF.  A signed-int compare here would treat that as a
 * negative "hi", skip the guard, and let the kernel walk
 * [a1, 0xFFFFFFFF] -- the exact path that closes the kcov fd at
 * PROTECTED_FD_HIGH_BASE.
 */
static bool keep_protected_fds_open(struct syscallrecord *rec)
{
	unsigned int lo = (unsigned int) rec->a1;
	unsigned int hi = (unsigned int) rec->a2;
	int lowest;

	/* The kernel refuses an inverted range before it closes anything. */
	if (lo > hi)
		return false;

	if (rec->a3 & CLOSE_RANGE_EXCEPT) {
		/*
		 * EXCEPT turns the range around: the kernel closes every fd
		 * outside [a1, a2] (marks it close-on-exec with CLOEXEC), so
		 * a protected fd is safe only inside it, and
		 * close_range(~0U, ~0U, EXCEPT) closes everything, the kcov
		 * fds included.  Truncating the range, as for a plain close
		 * below, would put more fds outside it, not fewer.  Widen it
		 * until it holds every protected fd, taking them lowest first
		 * since lowest_protected_fd_in_range() names only that one.
		 */
		unsigned int first = lo, last = hi, next = 0;

		while ((lowest = lowest_protected_fd_in_range(next, UINT_MAX)) >= 0) {
			if ((unsigned int) lowest < first)
				first = (unsigned int) lowest;
			if ((unsigned int) lowest > last)
				last = (unsigned int) lowest;
			next = (unsigned int) lowest + 1;
		}
		if (first == lo && last == hi)
			return false;
		rec->a1 = first;
		rec->a2 = last;
		return true;
	}

	/*
	 * If the picked range sweeps over a protected fd, truncate the upper
	 * bound so the kernel never sees the protected slot.  CLOEXEC calls
	 * just mark fds, but doing the truncation unconditionally keeps the
	 * snapshot the post handler reads consistent with the kernel's view
	 * regardless of the flags bit.  If the truncation
	 * leaves no fds to close (lowest protected fd <= rec->a1) we
	 * collapse the range to a no-op (close_range(N, N - 1) returns
	 * -EINVAL) rather than issuing a side-effect-free syscall on an
	 * unrelated low slot.
	 */
	lowest = lowest_protected_fd_in_range(lo, hi);
	if (lowest < 0)
		return false;

	if ((unsigned int) lowest <= (unsigned int) rec->a1) {
		/* Whole range was at or above the lowest
		 * protected fd -- nothing left to close.
		 * Invert the bounds so the kernel rejects
		 * the call instead of issuing a walk. */
		rec->a2 = rec->a1 > 0 ? rec->a1 - 1UL : 0UL;
	} else {
		rec->a2 = (unsigned long) lowest - 1UL;
	}
	return true;
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

	/* Visible counter so the operator can SEE the guard firing -- a
	 * denominator for the first_ebadf=...: closer=nr<close_range>[/prot]
	 * diag readings.  Zero means the picker never landed on a range that
	 * reached a protected fd; non-zero means the guard rewrote N calls
	 * and the kernel never saw the protected slot in what it would
	 * close. */
	if (keep_protected_fds_open(rec) && kcov_shm != NULL)
		__atomic_fetch_add(
			&kcov_shm->pc_diag.close_range_protect_truncate_count,
			1UL, __ATOMIC_RELAXED);

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic  = CLOSE_RANGE_POST_STATE_MAGIC;
	snap->fd     = (unsigned int) rec->a1;
	snap->max_fd = (unsigned int) rec->a2;
	snap->flags  = (unsigned int) rec->a3;
	post_state_install(rec, snap);
}

/*
 * CLOEXEC_ONLY closes only what was close-on-exec, and the call does not
 * say which numbers those were, so ask the kernel: F_GETFD fails with
 * EBADF for a number that is no longer open.  What it finds gone is
 * reported here, so the child's snapshots and the parent hear of those
 * numbers and of no open one.  Several objects can name one number, and
 * each asks again.
 */
static bool fd_is_closed(int fd)
{
	struct childdata *child;

	if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
		return false;

	child = this_child();
	if (child != NULL)
		notify_child_fd_closed(child, fd);
	return true;
}

/*
 * Retire the local objects under [lo, hi], numbers a successful
 * close_range closed, and report the close.
 */
static void close_span(unsigned int lo, unsigned int hi, unsigned int flags)
{
	struct childdata *child;

	/*
	 * Trinity routinely fuzzes this syscall with negative values.
	 * The bounds are unsigned bit patterns, so a well-formed range of
	 * negatives (hi just above lo as signed ints) glides through the
	 * 1024-fd clamp below and ends up enqueueing a CLOSE_RANGE whose
	 * lower end casts back to a negative fd.  The parent ring rejects
	 * it via fd_event_payload_valid(), but each rejection is logged, so
	 * a stream of such calls spams corrupt-event messages.  Bail --
	 * the parent has nothing to do with negative fds anyway.
	 */
	if ((int) lo < 0)
		return;

	/* The call did not close every fd in the span, so there is no
	 * range to report: fd_is_closed() reports each one it finds gone. */
	if (flags & CLOSE_RANGE_CLOEXEC_ONLY) {
		remove_local_objects_in_range(lo, hi, fd_is_closed);
		return;
	}

	/*
	 * A local object under a closed number names a file that is gone.
	 * The span is not capped like the report below: the pool is what
	 * gets walked, and hi can be as large as ~0U.
	 */
	remove_local_objects_in_range(lo, hi, NULL);

	/* Sanity: cap the reported span at 1025 fds */
	if (hi - lo > 1024)
		hi = lo + 1024;
	if (hi > INT_MAX)
		hi = INT_MAX;

	child = this_child();

	/* Publish one CLOSE_RANGE event and drop this child's local
	 * snapshots for the whole range in one shot.  Single pass over
	 * fd_hash[] and the 16-slot live-fd ring instead of per-fd
	 * walks. */
	if (child != NULL)
		notify_child_fd_closed_range(child, (int) lo, (int) hi);
}

/*
 * If close_range succeeded without CLOEXEC flag, the fds the flags pick
 * out are actually closed: [fd, max_fd], or with EXCEPT everything
 * outside it, and with CLOEXEC_ONLY just those of them that were
 * close-on-exec.  Enqueue the close for the parent, drop it from this
 * child's local snapshots, and retire the local objects under the
 * numbers it closed.
 *
 * The fd/max_fd/flags values are read from the post_state snapshot so
 * a sibling scribbling rec->aN between syscall return and post entry
 * cannot mis-direct the close-event enqueue or trigger the unsigned
 * `max_fd - fd` underflow described above the post_state struct.
 */
static void post_close_range(struct syscallrecord *rec)
{
	struct close_range_post_state *snap;
	unsigned int fd, max_fd, flags;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, CLOSE_RANGE_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if (rec->retval != 0)
		goto out_free;

	fd     = snap->fd;
	max_fd = snap->max_fd;
	flags  = snap->flags;

	/* CLOEXEC just marks fds, doesn't close them yet */
	if (flags & CLOSE_RANGE_CLOEXEC)
		goto out_free;

	/* The kernel answers a flags word it does not know with EINVAL, so
	 * a snapshot that holds one is not a call that closed anything. */
	if (flags & ~(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC |
		      CLOSE_RANGE_EXCEPT | CLOSE_RANGE_CLOEXEC_ONLY))
		goto out_free;

	/*
	 * Guard the unsigned subtraction in close_span().  A snapshot with
	 * max_fd < fd is either a kernel that accepted an inverted range
	 * (it should not) or a snapshot whose inner fields were
	 * wholesale-stomped after the magic check; either way, skip the
	 * close report rather than underflow `max_fd - fd` into a huge
	 * value that the 1024 clamp then turns into a 1025-fd span
	 * starting at a fd the original syscall never touched.
	 */
	if (max_fd < fd)
		goto out_free;

	/*
	 * UNSHARE does not change which numbers close: unshared, the table
	 * the caller keeps is a copy that lacks them.  EXCEPT closes the
	 * rest of the table, the span below fd and the one above max_fd.
	 */
	if (flags & CLOSE_RANGE_EXCEPT) {
		if (fd > 0)
			close_span(0, fd - 1, flags);
		if (max_fd < UINT_MAX)
			close_span(max_fd + 1, UINT_MAX, flags);
	} else {
		close_span(fd, max_fd, flags);
	}

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_close_range = {
	.name = "close_range",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_FD, [2] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "max_fd", [2] = "flags" },
	.arg_params[2].list = ARGLIST(close_range_flags),
	.sanitise = sanitise_close_range,
	.vet_final = vet_final_close_range,
	.post = post_close_range,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS_IO,
	/* Not REEXEC_SANITISE_OK: a RedQueen pin rewrites a slot after
	 * sanitise, and validate_arg_coupling() refuses a close_range whose
	 * slots changed since, so a pinned re-exec would only be refused. */
};
