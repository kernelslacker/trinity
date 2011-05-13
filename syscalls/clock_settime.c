/*
 * SYSCALL_DEFINE2(clock_settime, const clockid_t, which_clock, const struct timespec __user *, tp)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_clock_settime = {
	.name = "clock_settime",
	.num_args = 2,
	.arg1name = "which_clock",
	.arg2name = "tp",
	.arg2type = ARG_ADDRESS,
};
