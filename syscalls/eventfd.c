/*
 * SYSCALL_DEFINE1(eventfd, unsigned int, count)
 *
 * On success, eventfd() returns a new eventfd file descriptor.
 * On error, -1 is returned and errno is set to indicate the error.
 *
 * eventfd() calls eventfd2() with a zero'd flags arg.
 */
#include "sanitise.h"

struct syscallentry syscall_eventfd = {
	.name = "eventfd",
	.num_args = 1,
	.arg1name = "count",
	.arg1type = ARG_LEN,
	.rettype = RET_FD,
};

/*
 * SYSCALL_DEFINE2(eventfd2, unsigned int, count, int, flags)
 *
 * On success, eventfd() returns a new eventfd file descriptor.
 * On error, -1 is returned and errno is set to indicate the error.
 */

#include "sanitise.h"
#include "compat.h"

struct syscallentry syscall_eventfd2 = {
	.name = "eventfd2",
	.num_args = 2,
	.arg1name = "count",
	.arg1type = ARG_LEN,
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = {
		.num = 3,
		.values = { EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE },
	},
	.rettype = RET_FD,
};
