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
#include "random.h"
#include "sanitise.h"
#include "compat.h"

static unsigned long clock_nanosleep_which[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
	CLOCK_THREAD_CPUTIME_ID, CLOCK_BOOTTIME, CLOCK_TAI,
	CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM,
};

static unsigned long clock_nanosleep_flags[] = {
	TIMER_ABSTIME,
};

static void sanitise_clock_nanosleep(struct syscallrecord *rec)
{
	struct timespec *ts;

	ts = (struct timespec *) get_writable_address(sizeof(*ts));

	/* Keep sleep durations tiny so we don't block the fuzzer. */
	ts->tv_sec = 0;
	switch (rand() % 4) {
	case 0: ts->tv_nsec = 0; break;
	case 1: ts->tv_nsec = 1; break;
	case 2: ts->tv_nsec = rand() % 1000; break;		/* microsecond range */
	default: ts->tv_nsec = rand() % 1000000; break;	/* millisecond range */
	}

	rec->a3 = (unsigned long) ts;
}

struct syscallentry syscall_clock_nanosleep = {
	.name = "clock_nanosleep",
	.group = GROUP_TIME,
	.num_args = 4,
	.arg1name = "which_clock",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(clock_nanosleep_which),
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(clock_nanosleep_flags),
	.arg3name = "rqtp",
	.arg4name = "rmtp",
	.arg4type = ARG_ADDRESS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.sanitise = sanitise_clock_nanosleep,
};
