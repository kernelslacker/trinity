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
}

struct syscallentry syscall_timer_settime = {
	.name = "timer_settime",
	.group = GROUP_TIME,
	.num_args = 4,
	.arg1name = "timer_id",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = 31,
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(timer_settime_flags),
	.arg3name = "new_setting",
	.arg4name = "old_setting",
	.arg4type = ARG_ADDRESS,
	.sanitise = sanitise_timer_settime,
};
