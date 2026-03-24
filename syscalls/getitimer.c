/*
 * SYSCALL_DEFINE2(getitimer, int, which, struct itimerval __user *, value)
 */
#include <sys/time.h>
#include "sanitise.h"

static unsigned long getitimer_which[] = {
	ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF,
};

struct syscallentry syscall_getitimer = {
	.name = "getitimer",
	.group = GROUP_TIME,
	.num_args = 2,
	.arg1name = "which",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(getitimer_which),
	.arg2name = "value",
	.arg2type = ARG_NON_NULL_ADDRESS,
	.rettype = RET_ZERO_SUCCESS,
};
