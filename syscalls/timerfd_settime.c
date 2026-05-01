/*
 * SYSCALL_DEFINE4(timerfd_settime, int, ufd, int, flags,
	 const struct itimerspec __user *, utmr,
	 struct itimerspec __user *, otmr)
 */
#include <time.h>
#include <sys/timerfd.h>
#include "random.h"
#include "sanitise.h"

#ifndef TFD_TIMER_CANCEL_ON_SET
#define TFD_TIMER_CANCEL_ON_SET (1 << 1)
#endif

static unsigned long timerfd_settime_flags[] = {
	TFD_TIMER_ABSTIME, TFD_TIMER_CANCEL_ON_SET,
};

static void sanitise_timerfd_settime(struct syscallrecord *rec)
{
	struct itimerspec *its;

	its = (struct itimerspec *) get_writable_address(sizeof(*its));

	/* interval: 1-10 seconds */
	its->it_interval.tv_sec = 1 + (rand() % 10);
	its->it_interval.tv_nsec = 0;

	/* value: 1-10 seconds */
	its->it_value.tv_sec = 1 + (rand() % 10);
	its->it_value.tv_nsec = 0;

	rec->a3 = (unsigned long) its;
	avoid_shared_buffer(&rec->a4, sizeof(struct itimerspec));
}

struct syscallentry syscall_timerfd_settime = {
	.name = "timerfd_settime",
	.group = GROUP_TIME,
	.num_args = 4,
	.argtype = { [0] = ARG_FD_TIMERFD, [1] = ARG_LIST, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS },
	.argname = { [0] = "ufd", [1] = "flags", [2] = "utmr", [3] = "otmr" },
	.arg_params[1].list = ARGLIST(timerfd_settime_flags),
	.sanitise = sanitise_timerfd_settime,
	.flags = NEED_ALARM,
};
