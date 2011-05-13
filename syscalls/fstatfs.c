/*
 * SYSCALL_DEFINE2(fstatfs, unsigned int, fd, struct statfs __user *, buf)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_fstatfs = {
	.name = "fstatfs",
	.num_args = 2,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "buf",
	.arg2type = ARG_ADDRESS,
};
