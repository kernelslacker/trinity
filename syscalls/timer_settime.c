/*
 * SYSCALL_DEFINE4(timer_settime, timer_t, timer_id, int, flags,
	const struct itimerspec __user *, new_setting,
	struct itimerspec __user *, old_setting)
 */
#include <time.h>
#include "random.h"
#include "sanitise.h"

static unsigned long timer_settime_flags[] = {
	TIMER_ABSTIME,
};

static void fill_timespec(struct timespec *ts)
{
	switch (rand() % 5) {
	case 0: ts->tv_sec = 0; ts->tv_nsec = 0; break;
	case 1: ts->tv_sec = 0; ts->tv_nsec = 1; break;
	case 2: ts->tv_sec = 0; ts->tv_nsec = rand() % 1000000; break;
	case 3: ts->tv_sec = 1 + (rand() % 10); ts->tv_nsec = rand() % 1000000000; break;
	default: ts->tv_sec = rand32(); ts->tv_nsec = rand() % 1000000000; break;
	}
}

static void sanitise_timer_settime(struct syscallrecord *rec)
{
	struct itimerspec *its;

	its = (struct itimerspec *) get_writable_address(sizeof(*its));

	fill_timespec(&its->it_interval);
	fill_timespec(&its->it_value);

	/* Half the time, disarm the timer (zero it_value). */
	if (RAND_BOOL()) {
		its->it_value.tv_sec = 0;
		its->it_value.tv_nsec = 0;
	}

	rec->a3 = (unsigned long) its;
	avoid_shared_buffer(&rec->a4, sizeof(struct itimerspec));
}

struct syscallentry syscall_timer_settime = {
	.name = "timer_settime",
	.group = GROUP_TIME,
	.num_args = 4,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_LIST, [3] = ARG_ADDRESS },
	.argname = { [0] = "timer_id", [1] = "flags", [2] = "new_setting", [3] = "old_setting" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 31,
	.arg_params[1].list = ARGLIST(timer_settime_flags),
	.sanitise = sanitise_timer_settime,
};
