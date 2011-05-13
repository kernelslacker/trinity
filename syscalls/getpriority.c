/*
 * SYSCALL_DEFINE2(getpriority, int, which, int, who)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_getpriority = {
	.name = "getpriority",
	.num_args = 2,
	.arg1name = "which",
	.arg2name = "who",
};
