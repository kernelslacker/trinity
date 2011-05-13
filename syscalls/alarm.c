/*
 * SYSCALL_DEFINE1(alarm, unsigned int, seconds)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_alarm = {
	.name = "alarm",
	.num_args = 1,
	.arg1name = "seconds",
};
