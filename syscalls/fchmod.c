/*
 * SYSCALL_DEFINE2(fchmod, unsigned int, fd, mode_t, mode)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_fchmod = {
	.name = "fchmod",
	.num_args = 2,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "mode",
};
