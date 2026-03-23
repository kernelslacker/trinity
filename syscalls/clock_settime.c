/*
 * SYSCALL_DEFINE2(clock_settime, const clockid_t, which_clock, const struct timespec __user *, tp)
 *
 * return 0 for success, or -1 for failure (in which case errno is set appropriately).
 */
#include <time.h>
#include "random.h"
#include "sanitise.h"
#include "compat.h"

static unsigned long clock_ids[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
	CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE,
	CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME,
};

static void sanitise_clock_settime(struct syscallrecord *rec)
{
	struct timespec *ts;

	ts = (struct timespec *) get_writable_address(sizeof(*ts));

	switch (rand() % 5) {
	case 0:	/* epoch */
		ts->tv_sec = 0;
		ts->tv_nsec = 0;
		break;
	case 1: /* near-current (small offset) */
		ts->tv_sec = time(NULL) + (rand() % 120) - 60;
		ts->tv_nsec = rand() % 1000000000;
		break;
	case 2: /* boundary: max nsec */
		ts->tv_sec = rand32();
		ts->tv_nsec = 999999999;
		break;
	case 3: /* invalid nsec (>= 1 billion) */
		ts->tv_sec = rand32();
		ts->tv_nsec = 1000000000 + (rand() % 1000000000);
		break;
	default:
		ts->tv_sec = rand32();
		ts->tv_nsec = rand() % 1000000000;
		break;
	}

	rec->a2 = (unsigned long) ts;
}

struct syscallentry syscall_clock_settime = {
	.name = "clock_settime",
	.group = GROUP_TIME,
	.num_args = 2,
	.arg1name = "which_clock",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(clock_ids),
	.arg2name = "tp",
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEEDS_ROOT,
	.sanitise = sanitise_clock_settime,
};
