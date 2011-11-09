/*
 * SYSCALL_DEFINE1(eventfd, unsigned int, count)
 *
 * On success, eventfd() returns a new eventfd file descriptor.
 * On error, -1 is returned and errno is set to indicate the error.
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_eventfd = {
	.name = "eventfd",
	.num_args = 1,
	.arg1name = "count",
	.arg2type = ARG_LEN,
	.retval = ARG_FD,
};
