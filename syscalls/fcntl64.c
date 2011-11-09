/*
 * SYSCALL_DEFINE3(fcntl64, unsigned int, fd, unsigned int, cmd,
                 unsigned long, arg)
 *
 * For a successful call, the return value depends on the operation:
 *
 *     F_DUPFD The new descriptor.
 *     F_GETFD Value of file descriptor flags.
 *     F_GETFL Value of file status flags.
 *     F_GETLEASE Type of lease held on file descriptor.
 *     F_GETOWN Value of descriptor owner.
 *     F_GETSIG Value of signal sent when read or write becomes possible, or zero for traditional SIGIO behavior.
 *     F_GETPIPE_SZ The pipe capacity.
 *
 *     All other commands
 *              Zero.
 *
 *     On error, -1 is returned, and errno is set appropriately.
 *
 */
#include <linux/fcntl.h>
#include <unistd.h>
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_fcntl64 = {
	.name = "fcntl64",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "cmd",
	.arg2type = ARG_LIST,
	.arg2list = {
		.num = 7,
		.values = { F_DUPFD, F_GETFD, F_GETFL, F_GETLEASE, F_GETOWN, F_GETSIG, F_GETPIPE_SZ },
	},
	.arg3name = "arg",
};
