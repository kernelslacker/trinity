/*
 * SYSCALL_DEFINE3(fstatfs64, unsigned int, fd, size_t, sz, struct statfs64 __user *, buf)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_fstatfs64 = {
	.name = "fstatfs64",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "sz",
	.arg3name = "buf",
	.arg3type = ARG_ADDRESS,
};
