/*
 * SYSCALL_DEFINE2(clock_getres, const clockid_t, which_clock, struct timespec __user *, tp)
 *
 * return 0 for success, or -1 for failure (in which case errno is set appropriately).
 */
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include "deferred-free.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "clock-common.h"
#include "output-poison.h"

#include "kernel/time.h"
static unsigned long clock_ids[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
	CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE,
	CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME,
};

/*
 * Snapshot of the clock_getres tp buffer read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the source memcpy at a foreign user
 * buffer.  The clockid is read from the slot the kernel was handed
 * instead, which chain substitution or a RedQueen pin may have rewritten
 * after the sanitiser drew its own.  poison_seed is the per-call seed
 * poison_output_struct() stamped into the tp buffer at sanitise time; 0
 * means the poison arm was skipped (NULL tp) and the post handler must
 * skip the matching untouched-buffer check.
 */
#define CLOCK_GETRES_POST_STATE_MAGIC	0x43475253UL	/* "CGRS" */
struct clock_getres_post_state {
	unsigned long magic;
	unsigned long tp;
	uint64_t poison_seed;
};

static void sanitise_clock_getres(struct syscallrecord *rec)
{
	struct clock_getres_post_state *snap;

	rec->post_state = 0;

	/*
	 * Override the ARG_OP-generated clockid with a bucketed draw so
	 * we exercise the CPU-clock, dynamic-clock and invalid-clockid
	 * dispatch paths instead of only the trivial common-clock ones.
	 */
	rec->a1 = pick_clockid();

	avoid_shared_buffer_out(&rec->a2, sizeof(struct timespec));

	/*
	 * Snapshot the tp pointer for the post oracle.  Without this the
	 * post handler reads rec->a2 at post-time, when a sibling syscall
	 * may have scribbled the slot: looks_like_corrupted_ptr() cannot
	 * tell a real-but-wrong heap address from the original tp pointer.
	 * post_state is private to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic   = CLOCK_GETRES_POST_STATE_MAGIC;
	snap->tp      = rec->a2;

	/*
	 * clock_getres accepts a NULL tp -- clock_getres(clk, NULL) is a
	 * legal 0-byte success -- so gate the poison arm on tp != NULL.
	 * Stamping and then checking nothing would false-fire the
	 * untouched-buffer counter on every NULL call.  Poison after
	 * avoid_shared_buffer_out() so the pattern lands on the final
	 * buffer the kernel will see; the returned seed is fed back into
	 * check_output_struct() in the post handler.  poison_seed stays
	 * 0 on the NULL path and gates the post-side check.
	 */
	if (snap->tp != 0)
		snap->poison_seed = poison_output_struct((void *)(unsigned long) snap->tp,
							 sizeof(struct timespec),
							 0);

	post_state_install(rec, snap);
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
 * TOCTOU defeat: the user buffer pointer is snapshotted at sanitise time
 * into a heap struct in rec->post_state, so a sibling that scribbles
 * rec->a2 between syscall return and post entry cannot redirect the
 * source memcpy at a foreign user buffer.  The clockid is read from the
 * slot the kernel was handed: chain substitution or a RedQueen pin may
 * have rewritten it after the sanitiser, and a re-issue against the drawn
 * clock would resolve a different resolution and forge a divergence.  The
 * buffer payload is then snapshotted into a stack-local before the
 * re-call so a sibling-thread scribble of the user buffer itself after
 * the original return cannot drive a false divergence either.  If the
 * re-call fails, give up rather than report.  Compare tv_sec and tv_nsec
 * individually with no early-return so multi-field corruption surfaces in
 * a single sample, but bump the anomaly counter only once per sample.
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
	struct clock_getres_post_state *snap;
	clockid_t clockid;
	struct timespec first, recall;

	/*
	 * Canonical ownership bracket: shape -> ownership -> magic, in that
	 * order.  post_state_claim_owned() has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption counter
	 * on failure -- just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, CLOCK_GETRES_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->tp == 0)
		goto out_free;

	clockid = (clockid_t) get_arg_snapshot(rec, 1);

	if (!post_snapshot_or_skip(&first,
				   (const void *)(unsigned long) snap->tp,
				   sizeof(first)))
		goto out_free;

	/*
	 * Untouched-buffer check: clock_getres reported success but the
	 * user buffer still byte-for-byte matches the poison we stamped
	 * at sanitise time -- the kernel never called copy_to_user() at
	 * all, or short-copied and left an uninitialised-field tail
	 * readable in user memory (a kernel->user infoleak).  Cheap
	 * (byte-walk against a repeating 8-byte pattern, no re-issue),
	 * so runs on every sampled success.  Guarded on poison_seed so
	 * the NULL-tp sanitise path (poison arm skipped) can't false-
	 * fire against a pattern that was never laid down.  An intact
	 * poison pattern has bytes well outside a legitimate timespec
	 * range so the tv_nsec/tv_sec divergence oracle below will fire
	 * too, but this counter is the dedicated no-re-issue signal.
	 */
	if (snap->poison_seed &&
	    check_output_struct(&first, sizeof(first), snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);
	/* After the poison check, which wants the bytes as written. */
	time_struct_from_abi(rec, &first, 1);

	if (syscall(SYS_clock_getres, clockid, &recall) != 0)
		goto out_free;

	if (first.tv_sec != recall.tv_sec ||
	    first.tv_nsec != recall.tv_nsec) {
		output(0,
		       "[oracle:clock_getres] clockid %d tv_sec %ld vs %ld tv_nsec %ld vs %ld\n",
		       (int) clockid,
		       (long) first.tv_sec, (long) recall.tv_sec,
		       (long) first.tv_nsec, (long) recall.tv_nsec);
		__atomic_add_fetch(&shm->stats.oracle.clock_getres_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
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
	/* which_clock (a1): post_clock_getres re-calls on it. */
	.arg_snapshot_mask = (1u << 0),
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};
