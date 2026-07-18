/*
 * SYSCALL_DEFINE1(times, struct tms __user *, tbuf)
 */
#include <sys/times.h>
#include "output-poison.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the one times input arg plus the poison seed read by the
 * post oracle, captured at sanitise time and consumed by the post handler.
 * Lives in rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning and
 * the post handler running cannot redirect the source memcpy at a foreign
 * user buffer or smear the poison seed against a heap page that happens
 * to still carry a residual pattern from an earlier call.  A poison_seed
 * of 0 means the sanitise-time writability check refused to stamp poison
 * for this call and the post handler must no-op the untouched-buffer
 * check.
 */
#define TIMES_POST_STATE_MAGIC	0x54494D53UL	/* "TIMS" */
struct times_post_state {
	unsigned long magic;
	unsigned long tbuf;
	uint64_t poison_seed;
};

static void sanitise_times(struct syscallrecord *rec)
{
	struct times_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a1, sizeof(struct tms));

	/*
	 * Snapshot the one input arg for the post oracle.  Without this
	 * the post handler reads rec->a1 at post-time, when a sibling
	 * syscall may have scribbled the slot: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original tbuf
	 * user-buffer pointer, so the source memcpy would touch a foreign
	 * allocation.  post_state is private to the post handler.
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_times() will then gate the snap through
	 * post_state_claim_owned() and prove ownership before dereferencing
	 * any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = TIMES_POST_STATE_MAGIC;
	snap->tbuf = rec->a1;
	/*
	 * Stamp a per-call poison pattern into the user buffer the kernel
	 * is about to fill.  The post handler feeds the seed back into
	 * check_output_struct(); a byte-identical poison after a non-error
	 * clock_t return means the kernel skipped copy_to_user() entirely
	 * -- times(2) promises to overwrite the whole struct tms on
	 * success.  Gate on range_readable_user() so a writable-pool draw
	 * that avoid_shared_buffer_out() moved to an address that is no
	 * longer provably mapped -- e.g. a sibling munmap between
	 * allocation and now, or the ARG_ADDRESS generator handing back
	 * NULL -- does not SIGSEGV the sanitiser inside
	 * poison_output_struct's byte-walk.  On skip, poison_seed stays 0
	 * and the post handler no-ops the poison check while the
	 * field-diff oracle still runs against snap->tbuf.  Done after
	 * avoid_shared_buffer_out() so the poison lands on the final
	 * buffer the kernel will see.
	 */
	{
		void *buf = (void *)(unsigned long) rec->a1;

		if (range_readable_user(buf, sizeof(struct tms)))
			snap->poison_seed = poison_output_struct(buf,
								 sizeof(struct tms),
								 0);
	}
	post_state_install(rec, snap);
}

/*
 * Oracle: times(&buf) returns the wall-clock value in clock_t ticks since
 * boot and copies a struct tms holding the calling process's cumulative CPU
 * accounting -- tms_utime/tms_stime for self, tms_cutime/tms_cstime for
 * already-reaped children -- out to the user buffer.  All five values are
 * monotonic counters: the wall-clock return advances with the timer tick
 * and never rewinds, and each tms_* field is a per-task accumulator the
 * kernel only ever increments.  A second call moments later must see every
 * field at least as large as the first.  A decrease is therefore not a
 * benign race but a corruption signal pointing at one of:
 *
 *   - copy_to_user mis-write: the kernel produced the right values but the
 *     destination address was partially mapped or wrong, leaving torn or
 *     stale bytes in the user buffer.
 *   - 32-bit-on-64-bit compat sign-extension bug: a regression in the
 *     compat copy could sign-extend a clock_t that should be unsigned-
 *     widened, flipping a small positive count into a huge negative one
 *     that compares as decreasing on the next read.
 *   - struct-layout mismatch on 32-on-64 emulation: adjacent fields
 *     shifted, so e.g. tms_stime lands in the tms_utime slot and a
 *     subsequent read with the right layout shows a smaller value where
 *     the larger one used to sit.
 *   - sibling-thread scribble of the user receive buffer between the
 *     syscall return and our post-hook re-read.
 *
 * TOCTOU defeat: the one input arg (tbuf) is snapshotted at sanitise time
 * into a heap struct in rec->post_state, so a sibling that scribbles
 * rec->a1 between syscall return and post entry cannot redirect the
 * source memcpy at a foreign user buffer.  The user-buffer payload at
 * tbuf is then snapshotted into a stack-local before the re-call so a
 * sibling thread cannot scribble it between the original syscall return
 * and the comparison.  Re-issue times() into a separate stack buffer; if
 * the re-call returns (clock_t)-1 give up rather than report a false
 * divergence.  Compare all five values with no early-return
 * so multi-field corruption surfaces in a single sample, and emit one log
 * line carrying both 5-tuples so the operator sees the full divergence
 * shape at once.  Bump the anomaly counter once per sample regardless of
 * how many fields decreased.  Sample one in a hundred to stay in line with
 * the rest of the oracle family.
 *
 * No benign drift sources here: both reads are forward-only counters from
 * the same task, so any decrease is real.  The audit anchor stands purely
 * to catch the corruption shapes above.
 */
static void post_times(struct syscallrecord *rec)
{
	struct times_post_state *snap;
	struct tms first, recall;
	unsigned long retval;
	clock_t syscall_r;
	clock_t r;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, TIMES_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	/*
	 * Snapshot rec->retval once.  rec lives in the child's shm
	 * region; the original post handler read rec->retval three
	 * times (the (clock_t)-1 guard, the r < retval comparison, and
	 * the divergence log line) so a sibling-child stomp via a
	 * fuzzed pointer or a signal-handler reschedule rewriting the
	 * slot between any two reads can pass the -1 guard with the
	 * original value, then drive the monotonicity check against a
	 * stomped value and log mismatched values that were never
	 * actually returned by the syscall.  Same multi-read race the
	 * epoll post handlers had (commit 48279ed126bb).
	 */
	retval = rec->retval;
	syscall_r = (clock_t) retval;

	/*
	 * Success gate for times(2): the syscall returns a clock_t, not
	 * 0-on-success, so the "did it succeed" test keys on retval !=
	 * (unsigned long)-1 rather than retval == 0.  Any other value --
	 * including 0 clock ticks moments after boot -- is a real success
	 * return, so the untouched-buffer check below must run for all of
	 * them.
	 */
	if (retval == (unsigned long) -1)
		goto out_release;

	if (snap->tbuf == 0)
		goto out_release;

	/*
	 * Untouched-buffer check: times returned a non-error clock_t but
	 * the user buffer still byte-for-byte matches the poison pattern
	 * we stamped at sanitise time -- the kernel never called
	 * copy_to_user() at all.  Runs on every success (no ONE_IN gate)
	 * because the check is a ~32-byte memcmp with no re-issue, so it
	 * stays cheap enough to fire every time; bumps the shared
	 * post_handler_untouched_out_buf slot.  Skip when poison_seed is
	 * 0: sanitise refused to stamp (unmapped or NULL tbuf) so there
	 * is no pattern to compare against.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->tbuf,
					     sizeof(struct tms),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_release;

	if (!post_snapshot_or_skip(&first,
				   (const void *)(unsigned long) snap->tbuf,
				   sizeof(first)))
		goto out_release;

	r = times(&recall);
	if (r == (clock_t) -1)
		goto out_release;

	if (r < syscall_r ||
	    recall.tms_utime  < first.tms_utime  ||
	    recall.tms_stime  < first.tms_stime  ||
	    recall.tms_cutime < first.tms_cutime ||
	    recall.tms_cstime < first.tms_cstime) {
		output(0,
		       "[oracle:times] retval %ld vs %ld utime %ld vs %ld stime %ld vs %ld cutime %ld vs %ld cstime %ld vs %ld\n",
		       (long) syscall_r, (long) r,
		       (long) first.tms_utime,  (long) recall.tms_utime,
		       (long) first.tms_stime,  (long) recall.tms_stime,
		       (long) first.tms_cutime, (long) recall.tms_cutime,
		       (long) first.tms_cstime, (long) recall.tms_cstime);
		__atomic_add_fetch(&shm->stats.oracle.times_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_times = {
	.name = "times",
	.group = GROUP_TIME,
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "tbuf" },
	.sanitise = sanitise_times,
	.post = post_times,
	.rettype = RET_BORING,
	.flags = REEXEC_SANITISE_OK,
};
