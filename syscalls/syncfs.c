/*
 * SYSCALL_DEFINE1(syncfs, int, fd)
 */

#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_syncfs = {
	.name = "syncfs",
	.num_args = 1,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.flags = NEED_ALARM,
};
