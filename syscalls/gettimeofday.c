/*
 * SYSCALL_DEFINE2(gettimeofday, struct timeval __user *, tv, struct timezone __user *, tz)
 */
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include "deferred-free.h"
#include "shm.h"
#include "random.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the one gettimeofday input arg read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the source memcpy at a foreign user
 * buffer.  The tz arg (rec->a2) is not snapshotted because the post
 * handler does not read the timezone payload -- the oracle compares only
 * the wall-clock seconds in tv against clock_gettime(CLOCK_REALTIME).
 */
struct gettimeofday_post_state {
	unsigned long tv;
};

static void sanitise_gettimeofday(struct syscallrecord *rec)
{
	struct gettimeofday_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer(&rec->a1, sizeof(struct timeval));
	avoid_shared_buffer(&rec->a2, sizeof(struct timezone));

	/*
	 * Snapshot the one input arg the post oracle reads.  Without this
	 * the post handler reads rec->a1 at post-time, when a sibling
	 * syscall may have scribbled the slot: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original tv
	 * user-buffer pointer, so the source memcpy would touch a foreign
	 * allocation.  post_state is private to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->tv = rec->a1;
	rec->post_state = (unsigned long) snap;
}

/*
 * Oracle: sys_gettimeofday writes the current wall-clock time into the
 * caller's struct timeval -- ultimately the same timekeeping subsystem
 * that backs clock_gettime(CLOCK_REALTIME).  A meaningful divergence
 * between the value the kernel just copied out and a back-to-back
 * clock_gettime read points at a real ABI break: copy_to_user landing
 * past or before the tv slot, a torn write to the user buffer, a stale
 * vsyscall page after a clock-jump, or a sign-extension bug on the
 * compat path.
 *
 * Tolerance is +/-5 seconds.  The two reads aren't atomic with respect
 * to each other: scheduler delay between sys_gettimeofday returning and
 * us calling clock_gettime, plus NTP slew across the gap, can
 * legitimately shift the second sample by a second or two.  A real ABI
 * break (truncation, wrap, sign extension, wrong slot) puts the values
 * days or years apart, well outside this window.
 *
 * We deliberately don't compare tv_usec.  Without atomic reads the
 * tolerance window would have to be impractically narrow to catch a
 * real break without drowning in false positives from the gap between
 * the two samples.
 *
 * TOCTOU defeat: the tv input arg is snapshotted at sanitise time into
 * a heap struct in rec->post_state, so a sibling that scribbles rec->a1
 * between syscall return and post entry cannot redirect the source
 * memcpy at a foreign user buffer.  The user-buffer payload at tv is
 * then memcpy'd into a stack-local before inspection so a concurrent
 * thread can't mutate the user buffer between our checks.  Sample only
 * successful returns with a non-NULL tv; sanitised pointers can produce
 * -EFAULT and that's not an oracle violation.  ONE_IN(100) keeps the
 * extra clock_gettime cost in line with the rest of the oracle family.
 */
static void post_gettimeofday(struct syscallrecord *rec)
{
	struct gettimeofday_post_state *snap =
		(struct gettimeofday_post_state *) rec->post_state;
	struct timeval local_tv;
	struct timespec ts;
	long diff;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_gettimeofday: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if (rec->retval != 0)
		goto out_free;

	if (snap->tv == 0)
		goto out_free;

	{
		void *tv = (void *)(unsigned long) snap->tv;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner tv
		 * field.  Reject pid-scribbled tv before deref.
		 */
		if (looks_like_corrupted_ptr(rec, tv)) {
			outputerr("post_gettimeofday: rejected suspicious tv=%p (post_state-scribbled?)\n",
				  tv);
			goto out_free;
		}
	}

	memcpy(&local_tv, (void *)(unsigned long) snap->tv, sizeof(local_tv));

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		goto out_free;

	diff = (long) local_tv.tv_sec - (long) ts.tv_sec;

	if (diff < -5 || diff > 5) {
		output(0, "gettimeofday oracle: tv.tv_sec=%ld but clock_gettime=%ld (diff=%ld)\n",
		       (long) local_tv.tv_sec, (long) ts.tv_sec, diff);
		__atomic_add_fetch(&shm->stats.gettimeofday_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_gettimeofday = {
	.name = "gettimeofday",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "tv", [1] = "tz" },
	.sanitise = sanitise_gettimeofday,
	.rettype = RET_ZERO_SUCCESS,
	.post = post_gettimeofday,
};
