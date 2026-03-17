/*
 * SYSCALL_DEFINE2(getitimer, int, which, struct itimerval __user *, value)
 */
#include "sanitise.h"

struct syscallentry syscall_getitimer = {
	.name = "getitimer",
	.group = GROUP_TIME,
	.num_args = 2,
	.arg1name = "which",
	.arg2name = "value",
	.arg2type = ARG_ADDRESS,
	.rettype = RET_ZERO_SUCCESS,
};
