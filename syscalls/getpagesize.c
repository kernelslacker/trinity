/*
 * sys_getpagesize (void)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_getpagesize = {
	.flags = BORING,
	.name = "getpagesize",
	.num_args = 0,
};
