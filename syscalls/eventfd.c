/*
 * SYSCALL_DEFINE1(eventfd, unsigned int, count)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_eventfd = {
	.name = "eventfd",
	.num_args = 1,
	.arg1name = "count",
	.arg2type = ARG_LEN,
};
