/*
 * SYSCALL_DEFINE1(stime, time_t __user *, tptr)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_stime = {
	.name = "stime",
	.num_args = 1,
	.arg1name = "tptr",
	.arg1type = ARG_ADDRESS,
};
