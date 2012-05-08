/*
 * SYSCALL_DEFINE3(mknod, const char __user *, filename, int, mode, unsigned, dev)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_mknod = {
	.name = "mknod",
	.num_args = 3,
	.arg1name = "filename",
	.arg1type = ARG_PATHNAME,
	.arg2name = "mode",
	.arg3name = "dev",
};
