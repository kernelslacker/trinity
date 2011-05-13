/*
 * SYSCALL_DEFINE2(shutdown, int, fd, int, how)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_shutdown = {
	.name = "shutdown",
	.num_args = 2,
	.arg1name = "fd",
	.arg1type = ARG_FD,
};
