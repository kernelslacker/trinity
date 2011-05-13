/*
 * SYSCALL_DEFINE2(flock, unsigned int, fd, unsigned int, cmd)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_flock = {
	.name = "flock",
	.num_args = 2,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "cmd",
};
