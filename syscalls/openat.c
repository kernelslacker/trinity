/*
 * SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename, int, flags, int, mode)
 */
#include <fcntl.h>

#include "trinity.h"
#include "sanitise.h"

#ifndef O_PATH
#define O_PATH        010000000 /* Resolve pathname but do not open file.  */
#endif

struct syscall syscall_openat = {
	.name = "openat",
	.num_args = 4,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_ADDRESS,
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = {
		.num = 19,
		.values = { O_RDONLY, O_WRONLY, O_RDWR,
				O_CREAT, O_EXCL, O_NOCTTY,
				O_TRUNC, O_APPEND, O_NONBLOCK,
				O_SYNC, O_ASYNC,
				O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC,
				O_DIRECT, O_NOATIME, O_PATH,
				O_DSYNC, O_LARGEFILE },
	},
	.arg4name = "mode",
};
