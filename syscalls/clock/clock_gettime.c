/*
 * SYSCALL_DEFINE2(clock_gettime, const clockid_t, which_clock, struct timespec __user *,tp)
 *
 * return 0 for success, or -1 for failure (in which case errno is set appropriately).
 */
#include <sys/syscall.h>
#include <time.h>
#include "deferred-free.h"
#include "output-poison.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "clock-common.h"

#include "kernel/time.h"
static unsigned long clock_ids[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
	CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE,
	CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME,
};

#if defined(SYS_clock_gettime) || defined(__NR_clock_gettime)
/*
 * Snapshot of the two clock_gettime input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the source memcpy at a foreign user
 * buffer or smear the clockid the per-clock invariant set is keyed off.
 */
#define CLOCK_GETTIME_POST_STATE_MAGIC	0x4347544DUL	/* "CGTM" */
struct clock_gettime_post_state {
	unsigned long magic;
	unsigned long clockid;
	unsigned long tp;
	/*
	 * Seed for the poison pattern stamped into the tp OUT buffer at
	 * sanitise time.  Fed back into check_output_struct_user_or_skip()
	 * in the post handler so a stomp of rec->a2 cannot redirect the
	 * check against an unrelated heap page that happens to still carry
	 * the original (or any) byte pattern.
	 */
	uint64_t poison_seed;
};
#endif

static void sanitise_clock_gettime(struct syscallrecord *rec)
{
#if defined(SYS_clock_gettime) || defined(__NR_clock_gettime)
	struct clock_gettime_post_state *snap;

	rec->post_state = 0;
#endif

	/*
	 * Override the ARG_OP-generated clockid with a bucketed draw so
	 * we exercise the CPU-clock, dynamic-clock and invalid-clockid
	 * dispatch paths instead of only the trivial common-clock ones.
	 */
	rec->a1 = pick_clockid();

	avoid_shared_buffer_out(&rec->a2, sizeof(struct timespec));

#if defined(SYS_clock_gettime) || defined(__NR_clock_gettime)
	/*
	 * Snapshot the two input args for the post oracle.  Without this
	 * the post handler reads rec->a1/a2 at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original tp
	 * pointer, so the source memcpy would touch a foreign allocation.
	 * post_state is private to the post handler.  Gated on
	 * SYS_clock_gettime / __NR_clock_gettime to mirror the .post
	 * registration -- on systems without the syscall the post handler
	 * is not registered and a snapshot only the post handler can free
	 * would leak.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic   = CLOCK_GETTIME_POST_STATE_MAGIC;
	snap->clockid = rec->a1;
	snap->tp      = rec->a2;
	snap->poison_seed = 0;
	/*
	 * Stamp a per-call poison pattern into the user buffer the kernel
	 * is about to fill.  The post handler asks check_output_struct()
	 * whether the pattern survived intact; if it did on a success
	 * return the kernel wrote zero bytes despite reporting success.
	 * Done after avoid_shared_buffer_out() so the poison lands on the
	 * final buffer the kernel will see (the relocation may have
	 * swapped rec->a2 for a fresh page).  Gated on range_readable_user()
	 * so an ARG_NON_NULL_ADDRESS draw that landed on an address the
	 * writable-pool did not relocate does not SIGSEGV the sanitiser
	 * inside poison_output_struct's byte-walk; on skip poison_seed
	 * stays 0 and the post handler no-ops the untouched-buffer arm.
	 */
	if (range_readable_user((void *)(unsigned long) rec->a2,
				sizeof(struct timespec)))
		snap->poison_seed =
			poison_output_struct((void *)(unsigned long) rec->a2,
					     sizeof(struct timespec), 0);
	post_state_install(rec, snap);
#endif
}

#if defined(SYS_clock_gettime) || defined(__NR_clock_gettime)
/*
 * Oracle: clock_gettime(2) writes a struct timespec into the user
 * buffer.  We can't re-call clock_gettime and compare values — every
 * supported clock_id either advances monotonically or drifts in
 * wall-clock terms, so a re-call would diverge against the first
 * reading and produce a false-positive storm.  Instead, range-check
 * the timespec the kernel just wrote against the hard invariants every
 * clock_id in trinity's clock_ids[] table satisfies in normal
 * operation:
 *
 *   tv_nsec in [0..999999999]   (kernel-side hard invariant)
 *   tv_sec  >= 0                (true for every clock_id we exercise:
 *                                REALTIME and REALTIME_COARSE need a
 *                                pre-1970 wall clock to violate;
 *                                MONOTONIC/BOOTTIME/CPUTIME variants
 *                                count from a non-negative epoch by
 *                                construction)
 *
 * The user buffer is snapshotted into a local struct BEFORE either
 * range check so a sibling thread that scribbles the buffer between
 * syscall return and the post-hook read can't smear the comparison.
 *
 * Per-field bumps with no early-return so simultaneous tv_nsec+tv_sec
 * corruption surfaces as two anomalies in the same sample.
 *
 * False-positive sources at ONE_IN(100):
 *   - tv_nsec range: NONE.  1e9 is a hard kernel invariant; any
 *     violation is a real corruption.
 *   - tv_sec >= 0: NONE practical.  Would require a wall clock set
 *     before the Unix epoch (REALTIME) or a kernel that ships a
 *     negative monotonic base — not survivable for normal operation.
 *
 * Corruption shapes this catches:
 *   - copy_to_user mis-write past or before the timespec slot.
 *   - 32-on-64 compat path truncation of tv_nsec or tv_sec (would
 *     shift bits into the wrong field).
 *   - Stale percpu/vDSO data after a clock-source switch.
 *   - Sibling-thread scribble of the user buffer between syscall
 *     return and the post-hook read — caught because the snapshot
 *     happens before the cross-check.
 *
 * A second oracle bumps shm->stats.post_handler_untouched_out_buf
 * when the per-call poison pattern stamped at sanitise time survives
 * a success return: the kernel reported 0 but wrote zero bytes into
 * the timespec — a torn copy_to_user, a "return 0 before fill" early
 * exit, or a mis-wired compat wrapper.  The range oracle above can't
 * catch this because an untouched buffer still carries a byte pattern
 * that may happen to parse as a plausible timespec.
 *
 * Wrapped in #if defined(SYS_clock_gettime) || defined(__NR_clock_gettime)
 * for consistency with the rest of the oracle batch; clock_gettime has
 * been in Linux since 2.6 but minimal libcs may omit the macro.
 */
static void post_clock_gettime(struct syscallrecord *rec)
{
	struct clock_gettime_post_state *snap;
	struct timespec ts_user;

	/*
	 * Canonical ownership bracket: shape -> ownership -> magic, in that
	 * order.  post_state_claim_owned() has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption counter
	 * on failure -- just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, CLOCK_GETTIME_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if (rec->retval != 0)
		goto out_free;
	if (snap->tp == 0)
		goto out_free;

	/*
	 * Untouched-buffer oracle: no false positives, runs every success.
	 * poison_seed == 0 is the sanitise-refused-to-stamp sentinel; skip
	 * the check in that case rather than reading an unstamped buffer
	 * against a fixed pattern.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->tp,
					     sizeof(struct timespec),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_free;

	/*
	 * Snapshot the user buffer first so a sibling thread can't
	 * scribble it between the snapshot and the range checks.
	 */
	if (!post_snapshot_or_skip(&ts_user,
				   (const void *)(unsigned long) snap->tp,
				   sizeof(ts_user)))
		goto out_free;

	if (ts_user.tv_nsec < 0 || ts_user.tv_nsec >= 1000000000) {
		output(0, "clock_gettime oracle: tv_nsec=%ld out of [0..999999999]\n",
		       (long)ts_user.tv_nsec);
		__atomic_add_fetch(&shm->stats.oracle.clock_gettime_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

	if (ts_user.tv_sec < 0) {
		output(0, "clock_gettime oracle: tv_sec=%lld negative\n",
		       (long long)ts_user.tv_sec);
		__atomic_add_fetch(&shm->stats.oracle.clock_gettime_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}
#endif

struct syscallentry syscall_clock_gettime = {
	.name = "clock_gettime",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "which_clock", [1] = "tp" },
	.arg_params[0].list = ARGLIST(clock_ids),
	.sanitise = sanitise_clock_gettime,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
#if defined(SYS_clock_gettime) || defined(__NR_clock_gettime)
	.post = post_clock_gettime,
#endif
};
