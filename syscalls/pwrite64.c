/*
 * SYSCALL_DEFINE(pwrite64)(unsigned int fd, const char __user *buf, size_t count, loff_t po>
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_pwrite64 = {
	.name = "pwrite64",
	.num_args = 4,
	.sanitise = sanitise_pwrite64,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "buf",
	.arg2type = ARG_ADDRESS,
	.arg3name = "count",
	.arg4name = "pos",
};
