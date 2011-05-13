/*
 * SYSCALL_DEFINE2(access, const char __user *, filename, int, mode)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_access = {
	.name = "access",
	.num_args = 2,
	.arg1name = "filename",
	.arg1type = ARG_ADDRESS,
	.arg2name = "mode",
};
