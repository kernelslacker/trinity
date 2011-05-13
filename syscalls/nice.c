/*
 * SYSCALL_DEFINE1(nice, int, increment)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_nice = {
	.name = "nice",
	.num_args = 1,
	.arg1name = "increment",
};
