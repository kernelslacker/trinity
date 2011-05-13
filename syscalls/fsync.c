/*
 * SYSCALL_DEFINE1(fsync, unsigned int, fd)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_fsync = {
	.name = "fsync",
	.num_args = 1,
	.arg1name = "fd",
	.arg1type = ARG_FD,
};
