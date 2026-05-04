/*
 * SYSCALL_DEFINE2(clock_getres, const clockid_t, which_clock, struct timespec __user *, tp)
 *
 * return 0 for success, or -1 for failure (in which case errno is set appropriately).
 */
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"
#include "utils.h"

static unsigned long clock_ids[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
	CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE,
	CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME,
};

/*
 * Snapshot of the two clock_getres input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot retarget the re-issue at a different clockid or
 * redirect the source memcpy at a foreign user buffer.
 */
struct clock_getres_post_state {
	unsigned long clockid;
	unsigned long tp;
};

static void sanitise_clock_getres(struct syscallrecord *rec)
{
	struct clock_getres_post_state *snap;

	rec->post_state = 0;

	avoid_shared_buffer(&rec->a2, sizeof(struct timespec));

	/*
	 * Snapshot the two input args for the post oracle.  Without this
	 * the post handler reads rec->a1/a2 at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original tp
	 * pointer, and a stomped clockid would silently steer the re-issue
	 * at a different clock and forge a divergence.  post_state is
	 * private to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->clockid = rec->a1;
	snap->tp      = rec->a2;
	rec->post_state = (unsigned long) snap;
}

/*
 * Oracle: clock_getres(which_clock, &tp) writes the resolution of the named
 * clock — a {tv_sec, tv_nsec} pair — out to the user buffer.  The resolution
 * is a stable per-clockid kernel constant: it is the granularity of the
 * underlying timekeeping source (driver HZ for the coarse clocks, hrtimer
 * resolution for the high-res and CPU-time clocks, RTC granularity for the
 * RTC-backed ones), all set at boot or device probe and never mutated at
 * runtime for a given clockid.  Two reads of the same clock from the same
 * task therefore must produce byte-identical timespecs.  A divergence is not
 * benign drift — the kernel has no path that legitimately changes a clock's
 * resolution mid-run — it points at one of:
 *
 *   - copy_to_user mis-write: the kernel produced the right value but it
 *     landed in the wrong slot or arrived torn in the user buffer.
 *   - 32-bit-on-64-bit compat sign-extension or struct-layout mismatch on
 *     the timespec output: tv_sec / tv_nsec lanes swapped, or a 32-bit
 *     tv_sec sign-extended into a bogus 64-bit value.
 *   - sibling-thread scribble of the user receive buffer between the
 *     syscall return and our post-hook re-read.
 *
 * TOCTOU defeat (two arguments worth of it): the clockid and the user
 * buffer pointer are snapshotted at sanitise time into a heap struct in
 * rec->post_state, so a sibling that scribbles rec->a1/a2 between syscall
 * return and post entry cannot retarget the re-issue against a different
 * clockid (which would resolve a different resolution and forge a
 * divergence) or redirect the source memcpy at a foreign user buffer.
 * The buffer payload is then snapshotted into a stack-local before the
 * re-call so a sibling-thread scribble of the user buffer itself after
 * the original return cannot drive a false divergence either.  If the
 * re-call fails, give up rather than report.  Compare tv_sec and tv_nsec
 * individually with no early-return so multi-field corruption surfaces
 * in a single sample, but bump the anomaly counter only once per sample.
 * Emit one log line carrying both 2-tuples plus the clockid so the
 * operator sees the full divergence shape at once.  Sample one in a
 * hundred to stay in line with the rest of the oracle family.
 *
 * The dynamic clockids in clock_ids[] (CLOCK_PROCESS_CPUTIME_ID,
 * CLOCK_THREAD_CPUTIME_ID) resolve to per-task hrtimer resolution but the
 * resolution itself is still stable for the lifetime of the task, so they
 * need no extra gating.
 */
static void post_clock_getres(struct syscallrecord *rec)
{
	struct clock_getres_post_state *snap =
		(struct clock_getres_post_state *) rec->post_state;
	clockid_t clockid;
	struct timespec first, recall;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_clock_getres: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->tp == 0)
		goto out_free;

	clockid = (clockid_t) snap->clockid;

	{
		void *tp = (void *)(unsigned long) snap->tp;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner tp
		 * pointer field.  Reject pid-scribbled tp before deref.
		 */
		if (looks_like_corrupted_ptr(rec, tp)) {
			outputerr("post_clock_getres: rejected suspicious tp=%p (post_state-scribbled?)\n",
				  tp);
			goto out_free;
		}
	}

	memcpy(&first, (struct timespec *)(unsigned long) snap->tp,
	       sizeof(first));

	if (syscall(SYS_clock_getres, clockid, &recall) != 0)
		goto out_free;

	if (first.tv_sec != recall.tv_sec ||
	    first.tv_nsec != recall.tv_nsec) {
		output(0,
		       "[oracle:clock_getres] clockid %d tv_sec %ld vs %ld tv_nsec %ld vs %ld\n",
		       (int) clockid,
		       (long) first.tv_sec, (long) recall.tv_sec,
		       (long) first.tv_nsec, (long) recall.tv_nsec);
		__atomic_add_fetch(&shm->stats.clock_getres_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_clock_getres = {
	.name = "clock_getres",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_ADDRESS },
	.argname = { [0] = "which_clock", [1] = "tp" },
	.arg_params[0].list = ARGLIST(clock_ids),
	.sanitise = sanitise_clock_getres,
	.post = post_clock_getres,
	.rettype = RET_ZERO_SUCCESS,
};
