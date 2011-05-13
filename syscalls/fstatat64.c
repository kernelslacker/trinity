/*
 * SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,
	struct stat64 __user *, statbuf, int, flag)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_fstatat64 = {
	.name = "fstatat64",
	.num_args = 4,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_ADDRESS,
	.arg3name = "statbuf",
	.arg3type = ARG_ADDRESS,
	.arg4name = "flag",
};
