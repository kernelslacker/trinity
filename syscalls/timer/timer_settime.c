/*
 * SYSCALL_DEFINE4(timer_settime, timer_t, timer_id, int, flags,
	const struct itimerspec __user *, new_setting,
	struct itimerspec __user *, old_setting)
 */
#include <stdint.h>
#include <time.h>
#include "output-poison.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * new_setting (a3) is typed ARG_ITIMERSPEC; the generator publishes a
 * writable pool buffer (or NULL ~10%) and owns the bucketed it_value /
 * it_interval fill -- including the near-now (time(NULL)+1) bucket that
 * keeps a TIMER_ABSTIME deadline in the future.  The generator's
 * bucketed fill still ships tv_nsec >= 1e9 (case 6) or tv_sec < 0
 * (half of case 7) for either timespec in roughly a fifth of bucketed
 * calls; the kernel's timespec64_valid() check then short-circuits
 * with -EINVAL before posix_timer_set_common() ever runs and the real
 * hrtimer / per-clock expiry queue setup paths stay cold.  Layer a
 * valid-baseline overwrite on top so the bulk of calls arm the timer
 * (the generator's NULL / raw / disarm / bucketed arms still get
 * through whenever the dice come up against the overwrite, so the
 * timespec64_valid reject path stays warm).  The near-now bucket also
 * uses time(NULL) -- a wall-clock value -- which lands far in the
 * future when interpreted as a CLOCK_MONOTONIC absolute deadline (the
 * disposition of timers seeded by seed_timerid_if_empty), so the
 * valid-baseline arm builds its absolute deadline from CLOCK_MONOTONIC
 * for the TIMER_ABSTIME path.
 *
 * old_setting (a4) keeps ARG_ADDRESS + avoid_shared_buffer_out so the
 * kernel writeback never lands in the shared region.
 */
/*
 * Snapshot of the timer_settime old_setting pointer plus the poison seed
 * read by the post oracle, captured at sanitise time and consumed by the
 * post handler.  Lives in rec->post_state, a slot the syscall ABI does
 * not expose, so a sibling syscall scribbling rec->a4 between the
 * syscall returning and the post handler running cannot redirect the
 * poison check against an unrelated heap page whose residual bytes
 * happen to still match some earlier call's seed.  A poison_seed of 0
 * means the sanitise-time writability check refused to stamp poison for
 * this call (old_setting was NULL, or the writable draw was no longer
 * provably mapped) and the post handler must no-op the untouched-buffer
 * arm.
 */
#define TIMER_SETTIME_POST_STATE_MAGIC	0x54535454UL	/* "TSTT" */
struct timer_settime_post_state {
	unsigned long magic;
	unsigned long old_setting;
	uint64_t poison_seed;
};

static void fill_valid_timespec(struct timespec *ts)
{
	ts->tv_sec = (time_t) rnd_modulo_u32(5);
	ts->tv_nsec = (long) rnd_modulo_u32(1000000000u);
}

static void sanitise_timer_settime(struct syscallrecord *rec)
{
	struct timer_settime_post_state *snap;
	struct itimerspec *its;
	struct timespec now;
	void *buf;
	int32_t tid;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	/*
	 * Precondition: timer_id (a1) must reference a kernel-allocated
	 * k_itimer or timer_settime short-circuits with -EINVAL inside
	 * posix_timer_get_by_id() before the arm path runs.
	 * gen_arg_timerid returns a value from OBJ_TIMERID when the pool
	 * has entries, otherwise a random small int from
	 * get_random_timerid()'s pool-empty fallback that almost never
	 * matches a live id.  Seed one inline so timer_settime reaches
	 * the productive kernel arm path (hrtimer / per-clock expiry
	 * queue setup) on the very first call in the child.
	 */
	tid = seed_timerid_if_empty();
	if (tid >= 0)
		rec->a1 = (unsigned long) tid;

	rec->a2 = 0;
	if (ONE_IN(5))
		rec->a2 = TIMER_ABSTIME;

	/*
	 * Valid-baseline overwrite for the new_setting struct.  Skip
	 * when the generator handed us NULL (preserves the kernel's
	 * !new_setting EINVAL arm) and when the dice come up against
	 * (preserves the generator's raw / bucketed / disarm coverage,
	 * including the timespec64_valid reject path).  When it fires,
	 * fill both timespecs with values inside [0, 1e9) tv_nsec and a
	 * small non-negative tv_sec so timespec64_valid() accepts the
	 * struct and the call reaches posix_timer_set_common().  For
	 * TIMER_ABSTIME, build the it_value from CLOCK_MONOTONIC + a
	 * small offset so the absolute deadline lands in the future
	 * (the generator's near-now bucket uses time(NULL), which is
	 * wall-clock; the seeded timer in seed_timerid_if_empty() runs
	 * on CLOCK_MONOTONIC, so a wall-clock value used as a monotonic
	 * deadline schedules far past the typical run length).
	 * it_interval splits between a small valid periodic and zero so
	 * both the requeue and one-shot arm paths get exercised.
	 */
	its = (struct itimerspec *) rec->a3;
	if (its != NULL && rnd_modulo_u32(100) < 75) {
		fill_valid_timespec(&its->it_value);
		if (rec->a2 == TIMER_ABSTIME &&
		    clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
			its->it_value.tv_sec = now.tv_sec +
				(time_t) (1 + rnd_modulo_u32(5));
		}
		if (RAND_BOOL()) {
			fill_valid_timespec(&its->it_interval);
		} else {
			its->it_interval.tv_sec = 0;
			its->it_interval.tv_nsec = 0;
		}
	}

	avoid_shared_buffer_out(&rec->a4, sizeof(struct itimerspec));

	/*
	 * Snapshot the old_setting user pointer + a per-call poison seed
	 * for the post oracle.  Without the a4 snap the post handler
	 * reads rec->a4 at post-time, when a sibling syscall may have
	 * scribbled the slot: looks_like_corrupted_ptr() cannot tell a
	 * real-but-wrong heap address from the original old_setting
	 * user-buffer pointer, so the poison check would touch a foreign
	 * allocation.  post_state is private to the post handler.  Stamp
	 * the poison AFTER avoid_shared_buffer_out() so it lands on the
	 * final buffer the kernel will see; the returned seed is fed
	 * back into check_output_struct_user_or_skip() in the post
	 * handler.  range_readable_user() folds both the NULL gate
	 * (old_setting is ARG_ADDRESS, so a4 == 0 is a documented
	 * "don't write back") and the unmapped-address gate into one
	 * call: NULL and unproven ranges both return false, so
	 * poison_seed stays 0 (zmalloc_tracked cleared it) and the post
	 * handler no-ops the untouched-buffer arm.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = TIMER_SETTIME_POST_STATE_MAGIC;
	snap->old_setting = rec->a4;

	buf = (void *)(unsigned long) rec->a4;
	if (range_readable_user(buf, sizeof(struct itimerspec)))
		snap->poison_seed = poison_output_struct(buf,
							 sizeof(struct itimerspec),
							 0);

	post_state_install(rec, snap);
}

/*
 * Oracle: timer_settime(2) returns 0 on success and -1 on failure.  On
 * success, if old_setting != NULL the kernel writes the previously-armed
 * itimerspec (remaining time + reload interval) to *old_setting.  A
 * byte-identical poison pattern after success on a non-NULL old_setting
 * means the copy_to_user() path skipped the writeback entirely; bump
 * the shared post_handler_untouched_out_buf counter.  The NULL-arg path
 * and every error return are silent -- no writeback contract, no false
 * positives.
 *
 * Snapshot pattern matches the other output-poison oracles in this
 * subtree (timer_gettime, timerfd_gettime): the user out-pointer is
 * captured at sanitise time into a heap struct in rec->post_state so
 * a sibling scribbling rec->a4 between syscall return and post entry
 * cannot redirect the poison check against a foreign allocation.  The
 * snap is registered in the ownership table at install time and the
 * post handler gates entry through post_state_claim_owned(), which
 * runs the canonical shape -> ownership -> magic check before any
 * inner-field deref.
 */
static void post_timer_settime(struct syscallrecord *rec)
{
	struct timer_settime_post_state *snap =
		post_state_claim_owned(rec, TIMER_SETTIME_POST_STATE_MAGIC,
				       __func__);

	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_free;

	/*
	 * Untouched-buffer check: timer_settime returned 0 with a
	 * non-NULL old_setting, but the user buffer still byte-for-byte
	 * matches the poison pattern we stamped at sanitise time -- the
	 * kernel never called copy_to_user() at all.  A poison_seed of 0
	 * is the sanitise-refused-to-stamp signal (NULL old_setting or
	 * unmapped writable draw) -- gating on it here also doubles as
	 * the NULL-arg short-circuit, so no separate snap->old_setting
	 * == 0 check is needed.  Cheap (byte-walk against a repeating
	 * 8-byte pattern, no re-issue syscall), so runs on every success
	 * rather than under ONE_IN().
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((const void *)(unsigned long) snap->old_setting,
					     sizeof(struct itimerspec),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_timer_settime = {
	.name = "timer_settime",
	.group = GROUP_TIME,
	.num_args = 4,
	.argtype = { [0] = ARG_TIMERID, [2] = ARG_ITIMERSPEC, [3] = ARG_ADDRESS },
	.argname = { [0] = "timer_id", [1] = "flags", [2] = "new_setting", [3] = "old_setting" },
	.sanitise = sanitise_timer_settime,
	.post = post_timer_settime,
	.rettype = RET_ZERO_SUCCESS,
};
