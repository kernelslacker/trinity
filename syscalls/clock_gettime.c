/*
 * SYSCALL_DEFINE2(clock_gettime, const clockid_t, which_clock, struct timespec __user *,tp)
 *
 * return 0 for success, or -1 for failure (in which case errno is set appropriately).
 */
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "compat.h"
#include "utils.h"

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
struct clock_gettime_post_state {
	unsigned long clockid;
	unsigned long tp;
};
#endif

static void sanitise_clock_gettime(struct syscallrecord *rec)
{
#if defined(SYS_clock_gettime) || defined(__NR_clock_gettime)
	struct clock_gettime_post_state *snap;

	rec->post_state = 0;
#endif

	avoid_shared_buffer(&rec->a2, sizeof(struct timespec));

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
	snap = zmalloc(sizeof(*snap));
	snap->clockid = rec->a1;
	snap->tp      = rec->a2;
	rec->post_state = (unsigned long) snap;
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
 * Wrapped in #if defined(SYS_clock_gettime) || defined(__NR_clock_gettime)
 * for consistency with the rest of the oracle batch; clock_gettime has
 * been in Linux since 2.6 but minimal libcs may omit the macro.
 */
static void post_clock_gettime(struct syscallrecord *rec)
{
	struct clock_gettime_post_state *snap =
		(struct clock_gettime_post_state *) rec->post_state;
	struct timespec ts_user;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_clock_gettime: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if (rec->retval != 0)
		goto out_free;
	if (snap->tp == 0)
		goto out_free;

	{
		void *tp = (void *)(unsigned long) snap->tp;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner tp
		 * pointer field.  Reject pid-scribbled tp before deref.
		 */
		if (looks_like_corrupted_ptr(rec, tp)) {
			outputerr("post_clock_gettime: rejected suspicious tp=%p (post_state-scribbled?)\n",
				  tp);
			goto out_free;
		}
	}

	/*
	 * Snapshot the user buffer first so a sibling thread can't
	 * scribble it between the snapshot and the range checks.
	 */
	memcpy(&ts_user, (const void *)(unsigned long) snap->tp,
	       sizeof(ts_user));

	if (ts_user.tv_nsec < 0 || ts_user.tv_nsec >= 1000000000) {
		output(0, "clock_gettime oracle: tv_nsec=%ld out of [0..999999999]\n",
		       (long)ts_user.tv_nsec);
		__atomic_add_fetch(&shm->stats.clock_gettime_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

	if (ts_user.tv_sec < 0) {
		output(0, "clock_gettime oracle: tv_sec=%lld negative\n",
		       (long long)ts_user.tv_sec);
		__atomic_add_fetch(&shm->stats.clock_gettime_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
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
#if defined(SYS_clock_gettime) || defined(__NR_clock_gettime)
	.post = post_clock_gettime,
#endif
};
