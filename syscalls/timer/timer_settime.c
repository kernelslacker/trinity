/*
 * SYSCALL_DEFINE4(timer_settime, timer_t, timer_id, int, flags,
	const struct itimerspec __user *, new_setting,
	struct itimerspec __user *, old_setting)
 */
#include <stdint.h>
#include <time.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

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
static void fill_valid_timespec(struct timespec *ts)
{
	ts->tv_sec = (time_t) rnd_modulo_u32(5);
	ts->tv_nsec = (long) rnd_modulo_u32(1000000000u);
}

static void sanitise_timer_settime(struct syscallrecord *rec)
{
	struct itimerspec *its;
	struct timespec now;
	int32_t tid;

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
}

struct syscallentry syscall_timer_settime = {
	.name = "timer_settime",
	.group = GROUP_TIME,
	.num_args = 4,
	.argtype = { [0] = ARG_TIMERID, [2] = ARG_ITIMERSPEC, [3] = ARG_ADDRESS },
	.argname = { [0] = "timer_id", [1] = "flags", [2] = "new_setting", [3] = "old_setting" },
	.sanitise = sanitise_timer_settime,
	.rettype = RET_ZERO_SUCCESS,
};
