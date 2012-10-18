/*
 * SYSCALL_DEFINE2(setns, int, fd, int, nstype)
 */

#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_setns= {
	.name = "setns",
	.num_args = 2,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "nstype",
	.flags = NEED_ALARM,
};
