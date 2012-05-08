/*
 * SYSCALL_DEFINE2(chmod, const char __user *, filename, mode_t, mode)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_chmod = {
	.name = "chmod",
	.num_args = 2,
	.arg1name = "filename",
	.arg1type = ARG_PATHNAME,
	.arg2name = "mode",
	.rettype = RET_ZERO_SUCCESS,
};
