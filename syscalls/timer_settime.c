/*
 * SYSCALL_DEFINE4(timer_settime, timer_t, timer_id, int, flags,
	const struct itimerspec __user *, new_setting,
	struct itimerspec __user *, old_setting)
 */
#include <time.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

static void fill_nonzero_timespec(struct timespec *ts)
{
	switch (rnd_modulo_u32(4)) {
	case 0: ts->tv_sec = 0; ts->tv_nsec = 1; break;
	case 1: ts->tv_sec = 0; ts->tv_nsec = 1 + rnd_modulo_u32(1000000); break;
	case 2: ts->tv_sec = 1 + rnd_modulo_u32(10); ts->tv_nsec = rnd_modulo_u32(1000000000); break;
	default: ts->tv_sec = rand32(); ts->tv_nsec = rnd_modulo_u32(1000000000); break;
	}
}

static void sanitise_timer_settime(struct syscallrecord *rec)
{
	struct itimerspec *its;
	uint32_t bucket;

	its = (struct itimerspec *) get_writable_address(sizeof(*its));
	if (its == NULL)
		return;

	its->it_interval.tv_sec = 0;
	its->it_interval.tv_nsec = 0;
	its->it_value.tv_sec = 0;
	its->it_value.tv_nsec = 0;

	rec->a2 = 0;

	bucket = rnd_modulo_u32(100);
	if (bucket < 25) {
		/* disarm: it_value zeroed */
	} else if (bucket < 55) {
		/* one-shot: it_value > 0, it_interval = 0 */
		fill_nonzero_timespec(&its->it_value);
	} else if (bucket < 80) {
		/* periodic: both intervals > 0 */
		fill_nonzero_timespec(&its->it_value);
		fill_nonzero_timespec(&its->it_interval);
	} else {
		/* TIMER_ABSTIME with a near-now deadline so the kernel actually
		 * schedules the timer instead of firing it immediately on a
		 * deadline-in-the-past. */
		struct timespec now;

		if (clock_gettime(CLOCK_REALTIME, &now) == 0) {
			its->it_value.tv_sec = now.tv_sec + 1;
			its->it_value.tv_nsec = now.tv_nsec;
		} else {
			fill_nonzero_timespec(&its->it_value);
		}
		rec->a2 = TIMER_ABSTIME;
	}

	rec->a3 = (unsigned long) its;
	avoid_shared_buffer_out(&rec->a4, sizeof(struct itimerspec));
}

struct syscallentry syscall_timer_settime = {
	.name = "timer_settime",
	.group = GROUP_TIME,
	.num_args = 4,
	.argtype = { [0] = ARG_TIMERID, [3] = ARG_ADDRESS },
	.argname = { [0] = "timer_id", [1] = "flags", [2] = "new_setting", [3] = "old_setting" },
	.sanitise = sanitise_timer_settime,
	.rettype = RET_ZERO_SUCCESS,
};
