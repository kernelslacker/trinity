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
#include "trinity.h"
#include "utils.h"

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

	/*
	 * rmtp (a4) is the kernel's "remaining time on EINTR" output buffer:
	 * if the sleep is interrupted, the kernel writes the unslept residual
	 * timespec there.  Random pool can land it inside an alloc_shared
	 * region, so scrub.
	 */
	avoid_shared_buffer(&rec->a4, sizeof(struct timespec));
}

static void post_clock_nanosleep(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret != 0 && ret != -1L) {
		output(0, "post_clock_nanosleep: rejected retval %ld outside {0, -1}\n", ret);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

struct syscallentry syscall_clock_nanosleep = {
	.name = "clock_nanosleep",
	.group = GROUP_TIME,
	.num_args = 4,
	.argtype = { [0] = ARG_OP, [1] = ARG_LIST, [3] = ARG_ADDRESS },
	.argname = { [0] = "which_clock", [1] = "flags", [2] = "rqtp", [3] = "rmtp" },
	.arg_params[0].list = ARGLIST(clock_nanosleep_which),
	.arg_params[1].list = ARGLIST(clock_nanosleep_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.sanitise = sanitise_clock_nanosleep,
	.post = post_clock_nanosleep,
};
