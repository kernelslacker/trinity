/*
 * SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_faccessat = {
	.name = "faccessat",
	.num_args = 3,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_ADDRESS,
	.arg3name = "mode",
};
