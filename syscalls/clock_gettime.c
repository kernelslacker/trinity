/*
 * SYSCALL_DEFINE2(clock_gettime, const clockid_t, which_clock, struct timespec __user *,tp)
 *
 * return 0 for success, or -1 for failure (in which case errno is set appropriately).
 */
#include <time.h>
#include "sanitise.h"
#include "compat.h"

static unsigned long clock_ids[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
	CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE,
	CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME,
};

static void sanitise_clock_gettime(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, sizeof(struct timespec));
}

struct syscallentry syscall_clock_gettime = {
	.name = "clock_gettime",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "which_clock", [1] = "tp" },
	.arg_params[0].list = ARGLIST(clock_ids),
	.sanitise = sanitise_clock_gettime,
	.rettype = RET_ZERO_SUCCESS,
};
