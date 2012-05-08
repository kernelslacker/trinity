/*
 * SYSCALL_DEFINE2(mkdir, const char __user *, pathname, int, mode)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_mkdir = {
	.name = "mkdir",
	.num_args = 2,
	.arg1name = "pathname",
	.arg1type = ARG_PATHNAME,
	.arg2name = "mode",
};
