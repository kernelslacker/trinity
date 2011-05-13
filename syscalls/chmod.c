/*
 * SYSCALL_DEFINE2(chmod, const char __user *, filename, mode_t, mode)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_chmod = {
	.name = "chmod",
	.num_args = 2,
	.arg1name = "filename",
	.arg1type = ARG_ADDRESS,
	.arg2name = "mode",
};
