/*
 * SYSCALL_DEFINE1(close, unsigned int, fd)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_close = {
	.name = "close",
	.num_args = 1,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.flags = AVOID_SYSCALL,
};
