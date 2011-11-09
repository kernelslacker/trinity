/*
 * SYSCALL_DEFINE(fallocate)(int fd, int mode, loff_t offset, loff_t len)
 *
 * fallocate() returns zero on success, and -1 on failure.
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_fallocate = {
	.name = "fallocate",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "mode",
	.arg3name = "offset",
	.arg4name = "len",
	.arg4type = ARG_LEN,
};
