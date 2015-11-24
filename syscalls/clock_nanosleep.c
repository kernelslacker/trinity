/*
 * SYSCALL_DEFINE4(clock_nanosleep, const clockid_t, which_clock, int, flags,
	const struct timespec __user *, rqtp,
	struct timespec __user *, rmtp)
 *
 * On successfully sleeping for the requested interval, clock_nanosleep() returns 0.
 * If the call is interrupted by a signal handler or  encounters  an  error,
 *  then it returns one of the positive error number listed in ERRORS.
 */

#include <time.h>
#include "sanitise.h"

static unsigned long clock_nanosleep_which[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
};

static unsigned long clock_nanosleep_flags[] = {
	TIMER_ABSTIME,
};

struct syscallentry syscall_clock_nanosleep = {
	.name = "clock_nanosleep",
	.num_args = 4,
	.arg1name = "which_clock",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(clock_nanosleep_which),
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(clock_nanosleep_flags),
	.arg3name = "rqtp",
	.arg3type = ARG_ADDRESS,
	.arg4name = "rmtp",
	.arg4type = ARG_ADDRESS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
};
