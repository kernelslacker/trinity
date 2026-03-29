/*
 * SYSCALL_DEFINE4(timerfd_settime, int, ufd, int, flags,
	 const struct itimerspec __user *, utmr,
	 struct itimerspec __user *, otmr)
 */
#include <sys/timerfd.h>
#include "sanitise.h"

#ifndef TFD_CLOEXEC
#define TFD_CLOEXEC 02000000
#endif

#ifndef TFD_NONBLOCK
#define TFD_NONBLOCK 04000
#endif

#ifndef TFD_TIMER_CANCEL_ON_SET
#define TFD_TIMER_CANCEL_ON_SET (1 << 1)
#endif

static unsigned long timerfd_settime_flags[] = {
	TFD_NONBLOCK, TFD_CLOEXEC,
	TFD_TIMER_ABSTIME, TFD_TIMER_CANCEL_ON_SET,
};

struct syscallentry syscall_timerfd_settime = {
	.name = "timerfd_settime",
	.group = GROUP_TIME,
	.num_args = 4,
	.argtype = { [0] = ARG_FD_TIMERFD, [1] = ARG_LIST, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS },
	.argname = { [0] = "ufd", [1] = "flags", [2] = "utmr", [3] = "otmr" },
	.arg2list = ARGLIST(timerfd_settime_flags),
	.flags = NEED_ALARM,
};
