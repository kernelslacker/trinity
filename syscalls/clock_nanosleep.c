/*
 * SYSCALL_DEFINE4(clock_nanosleep, const clockid_t, which_clock, int, flags,
	const struct timespec __user *, rqtp,
	struct timespec __user *, rmtp)
 */

#include <time.h>

#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_clock_nanosleep = {
	.name = "clock_nanosleep",
	.num_args = 4,
	.arg1name = "which_clock",
	.arg1type = ARG_LIST,
	.arg1list = {
		.num = 3,
		.values = { CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID },
	},
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = {
		.num = 1,
		.values = { TIMER_ABSTIME },
	},
	.arg3name = "rqtp",
	.arg3type = ARG_ADDRESS,
	.arg4name = "rmtp",
	.arg4type = ARG_ADDRESS,
};
