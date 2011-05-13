/*
 * SYSCALL_DEFINE1(fchdir, unsigned int, fd)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_fchdir = {
	.name = "fchdir",
	.num_args = 1,
	.arg1name = "fd",
	.arg1type = ARG_FD,
};
