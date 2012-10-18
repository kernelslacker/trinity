/*
 * SYSCALL_DEFINE3(fcntl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
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
 */
#include <fcntl.h>
#include "trinity.h"
#include "sanitise.h"
#include "compat.h"

struct syscall syscall_fcntl = {
	.name = "fcntl",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "cmd",
	.arg2type = ARG_OP,
	.arg2list = {
		.num = 23,
		.values = { F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_GETLK, F_SETLK,
		  F_SETLKW, F_GETOWN, F_SETOWN, F_GETOWN_EX, F_SETOWN_EX, F_GETSIG, F_SETSIG, F_GETLEASE,
		  F_SETLEASE, F_NOTIFY, F_SETPIPE_SZ, F_GETPIPE_SZ, F_GETLK64, F_SETLK64, F_SETLKW64 },
	},
	.arg3name = "arg",
	.rettype = RET_FD,	//FIXME: Needs to mutate somehow depending on 'cmd'
	.flags = NEED_ALARM,
};
