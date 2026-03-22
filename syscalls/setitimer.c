/*
 * SYSCALL_DEFINE3(setitimer, int, which, struct itimerval __user *, value, struct itimerval __user *, ovalue)
 */
#include <sys/time.h>
#include "sanitise.h"

static unsigned long setitimer_which[] = {
	ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF,
};

struct syscallentry syscall_setitimer = {
	.flags = AVOID_SYSCALL,		/* setitimer interferes with alarm() */
	.name = "setitimer",
	.group = GROUP_TIME,
	.num_args = 3,
	.arg1name = "which",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(setitimer_which),
	.arg2name = "value",
	.arg2type = ARG_ADDRESS,
	.arg3name = "ovalue",
	.arg3type = ARG_ADDRESS,
};
