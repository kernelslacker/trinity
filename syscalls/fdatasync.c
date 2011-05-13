/*
 * SYSCALL_DEFINE1(fdatasync, unsigned int, fd)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_fdatasync = {
	.name = "fdatasync",
	.num_args = 1,
	.arg1name = "fd",
	.arg1type = ARG_FD,
};
