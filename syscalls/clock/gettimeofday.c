/*
 * SYSCALL_DEFINE2(gettimeofday, struct timeval __user *, tv, struct timezone __user *, tz)
 */
#include <sys/time.h>
#include <time.h>
#include "arch.h"
#include "deferred-free.h"
#include "output-poison.h"
#include "shm.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the two gettimeofday input args plus per-slot poison seeds
 * read by the post oracle, captured at sanitise time and consumed by the
 * post handler.  Lives in rec->post_state, a slot the syscall ABI does
 * not expose, so a sibling syscall scribbling rec->aN between the
 * syscall returning and the post handler running cannot redirect the
 * oracle at a foreign tv / tz user buffer or smear a poison check
 * against a heap page that happens to carry a residual pattern from an
 * earlier call.  Both slots are independently nullable -- the tz arg is
 * deliberately NULL half the time to fuzz the modern-caller path, and
 * the tv arg carries an intentional past-end-of-page fault 10% of the
 * time -- so each pointer / seed pair is checked on its own.  A
 * poison_seed of 0 means the sanitise-time writability check refused to
 * stamp poison for that slot (unmapped or NULL) and the post handler
 * must no-op that arm.
 */
#define GETTIMEOFDAY_POST_STATE_MAGIC	0x47544F44UL	/* "GTOD" */
struct gettimeofday_post_state {
	unsigned long magic;
	unsigned long tv;
	unsigned long tz;
	uint64_t poison_seed[2];
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

	/*
	 * tz bucket: half the time NULL (the modern callers all pass NULL
	 * here), half the time a sanitised non-NULL timezone for the
	 * legacy copy path.  Without this override ARG_NON_NULL_ADDRESS
	 * forces tz to a writable pool buffer 100% of the time and the
	 * NULL branch never gets fuzz coverage.
	 */
	if (RAND_BOOL())
		rec->a2 = 0;
	else
		avoid_shared_buffer_out(&rec->a2, sizeof(struct timezone));

	/*
	 * tv bucket: 10% intentional past-end-of-page fault to keep the
	 * copy_to_user reject path warm without relying on the random
	 * pool to land on a faulting pointer; otherwise scrub a real
	 * pool address as before.
	 */
	if (rnd_modulo_u32(10) == 0) {
		void *base = get_writable_address(sizeof(struct timeval));
		if (base != NULL)
			rec->a1 = (unsigned long) base + page_size;
		else
			avoid_shared_buffer_out(&rec->a1,
				sizeof(struct timeval));
	} else {
		avoid_shared_buffer_out(&rec->a1, sizeof(struct timeval));
	}

	/*
	 * Snapshot the two input args read by the post oracle.  Without
	 * this the post handler reads rec->a1/a2 at post-time, when a
	 * sibling syscall may have scribbled the slots:
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from the original tv / tz user-buffer pointers, so the
	 * source memcpy would touch a foreign allocation.  post_state is
	 * private to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = GETTIMEOFDAY_POST_STATE_MAGIC;
	snap->tv = rec->a1;
	snap->tz = rec->a2;
	snap->poison_seed[0] = 0;
	snap->poison_seed[1] = 0;

	/*
	 * Stamp a per-slot poison pattern into each of the tv / tz
	 * OUT-buffers the kernel is about to fill.  The post handler
	 * feeds each seed back into check_output_struct(); a byte-
	 * identical poison after a rec->retval == 0 return means the
	 * kernel wrote zero bytes into that struct and left our stamp
	 * intact -- gettimeofday(2) is contracted to overwrite tv on
	 * success, and to overwrite tz when it was passed non-NULL.
	 * Each slot is independently nullable, so skip stamping when the
	 * arg draw was 0.  Gate each stamp on range_readable_user() so a
	 * writable-pool draw that avoid_shared_buffer_out() moved to an
	 * address no longer provably mapped -- including the 10% tv
	 * branch that deliberately lands one page past a real allocation
	 * -- does not SIGSEGV the sanitiser inside poison_output_struct's
	 * byte-walk.  On skip the seed stays 0 and the post handler
	 * no-ops that arm.  Done after the address-picking above so the
	 * poison lands on the final buffer the kernel will see.
	 */
	{
		void *tv_buf = (void *)(unsigned long) rec->a1;
		void *tz_buf = (void *)(unsigned long) rec->a2;

		if (rec->a1 != 0 &&
		    range_readable_user(tv_buf, sizeof(struct timeval)))
			snap->poison_seed[0] =
				poison_output_struct(tv_buf,
						     sizeof(struct timeval),
						     0);
		if (rec->a2 != 0 &&
		    range_readable_user(tz_buf, sizeof(struct timezone)))
			snap->poison_seed[1] =
				poison_output_struct(tz_buf,
						     sizeof(struct timezone),
						     0);
	}

	post_state_install(rec, snap);
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
 * TOCTOU defeat: the tv and tz input args are snapshotted at sanitise
 * time into a heap struct in rec->post_state, so a sibling that
 * scribbles rec->a1 or rec->a2 between syscall return and post entry
 * cannot redirect the source memcpy at a foreign user buffer.  The
 * user-buffer payload at tv is then memcpy'd into a stack-local before
 * inspection so a concurrent thread can't mutate the user buffer
 * between our checks.  Sample only successful returns with a non-NULL
 * tv; sanitised pointers can produce -EFAULT and that's not an oracle
 * violation.  ONE_IN(100) keeps the extra clock_gettime cost in line
 * with the rest of the oracle family.
 */
static void post_gettimeofday(struct syscallrecord *rec)
{
	struct gettimeofday_post_state *snap;
	struct timeval local_tv;
	struct timezone local_tz;
	struct timespec ts;
	long diff;

	/*
	 * Canonical ownership bracket: shape -> ownership -> magic, in that
	 * order.  post_state_claim_owned() has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption counter
	 * on failure -- just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, GETTIMEOFDAY_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if (rec->retval != 0)
		goto out_free;

	/*
	 * Untouched-buffer poison check: sanitise stamped a per-slot
	 * poison pattern into each non-NULL tv / tz OUT-buffer.  A byte-
	 * identical match on a slot after a rec->retval == 0 return means
	 * the kernel wrote zero bytes into that struct and left our stamp
	 * intact -- a skipped copy_to_user() the wall-clock arm below
	 * would not detect on tz at all (that arm reads only tv.tv_sec)
	 * and would miss on tv 99 of 100 samples (the arm is rate-limited
	 * behind ONE_IN(100)).  Cheap (a struct-sized compare, no
	 * re-issue), so runs on every success sample.  Snapshot each slot
	 * into a local before the compare so a sibling munmap of the
	 * writable-pool page between the deref and here cannot fault
	 * inside a second read.  A seed of 0 means sanitise skipped that
	 * slot (unmapped or NULL) -- skip the check too so "we could not
	 * poison" is not confused with "kernel did not write".  Counts
	 * against the shared post_handler_untouched_out_buf slot.
	 */
	if (snap->tv != 0 && snap->poison_seed[0] != 0 &&
	    post_snapshot_or_skip(&local_tv,
				  (const void *)(unsigned long) snap->tv,
				  sizeof(local_tv)) &&
	    check_output_struct(&local_tv, sizeof(local_tv),
				snap->poison_seed[0]))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);
	if (snap->tz != 0 && snap->poison_seed[1] != 0 &&
	    post_snapshot_or_skip(&local_tz,
				  (const void *)(unsigned long) snap->tz,
				  sizeof(local_tz)) &&
	    check_output_struct(&local_tz, sizeof(local_tz),
				snap->poison_seed[1]))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_free;

	if (snap->tv == 0)
		goto out_free;

	if (!post_snapshot_or_skip(&local_tv,
				   (const void *)(unsigned long) snap->tv,
				   sizeof(local_tv)))
		goto out_free;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		goto out_free;

	diff = (long) local_tv.tv_sec - (long) ts.tv_sec;

	if (diff < -5 || diff > 5) {
		output(0, "gettimeofday oracle: tv.tv_sec=%ld but clock_gettime=%ld (diff=%ld)\n",
		       (long) local_tv.tv_sec, (long) ts.tv_sec, diff);
		__atomic_add_fetch(&shm->stats.oracle.gettimeofday_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
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
	.flags = REEXEC_SANITISE_OK,
};
