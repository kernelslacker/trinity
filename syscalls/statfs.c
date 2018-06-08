/*
 * SYSCALL_DEFINE2(statfs, const char __user *, pathname, struct statfs __user *, buf)
 */
#include "sanitise.h"

struct syscallentry syscall_statfs = {
	.name = "statfs",
	.num_args = 2,
	.arg1name = "pathname",
	.arg1type = ARG_PATHNAME,
	.arg2name = "buf",
	.arg2type = ARG_ADDRESS,
};

/*
 * SYSCALL_DEFINE3(statfs64, const char __user *, pathname, size_t, sz, struct statfs64 __user *, buf)
 */

struct syscallentry syscall_statfs64 = {
	.name = "statfs64",
	.num_args = 2,
	.arg1name = "pathname",
	.arg1type = ARG_PATHNAME,
	.arg2name = "sz",
	.arg3name = "buf",
	.arg3type = ARG_ADDRESS,
};
