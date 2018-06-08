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
	.num_args = 4,
	.arg1name = "ufd",
	.arg1type = ARG_FD,
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(timerfd_settime_flags),
	.arg3name = "utmr",
	.arg3type = ARG_ADDRESS,
	.arg4name = "otmr",
	.arg4type = ARG_ADDRESS,
	.flags = NEED_ALARM,
};
