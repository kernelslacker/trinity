/*
 * SYSCALL_DEFINE1(time, time_t __user *, tloc)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_time = {
	.name = "time",
	.num_args = 1,
	.arg1name = "tloc",
	.arg1type = ARG_ADDRESS,
};
