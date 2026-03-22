/*
 * SYSCALL_DEFINE4(timer_settime, timer_t, timer_id, int, flags,
	TIMER_ABSTIMEconst struct itimerspec __user *, new_setting,
	struct itimerspec __user *, old_setting)
 */
#include <time.h>
#include "sanitise.h"

static unsigned long timer_settime_flags[] = {
	TIMER_ABSTIME,
};

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
	.arg3type = ARG_ADDRESS,
	.arg4name = "old_setting",
	.arg4type = ARG_ADDRESS,
};
