/*
 * SYSCALL_DEFINE3(setitimer, int, which, struct itimerval __user *, value, struct itimerval __user *, ovalue)
 */
#include <sys/time.h>
#include "sanitise.h"

static unsigned long setitimer_which[] = {
	ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF,
};

static void sanitise_setitimer(struct syscallrecord *rec)
{
	avoid_shared_buffer_out(&rec->a3, sizeof(struct itimerval));
}

struct syscallentry syscall_setitimer = {
	.flags = AVOID_SYSCALL,		/* setitimer interferes with alarm() */
	.name = "setitimer",
	.group = GROUP_TIME,
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_ITIMERVAL, [2] = ARG_ADDRESS },
	.argname = { [0] = "which", [1] = "value", [2] = "ovalue" },
	.arg_params[0].list = ARGLIST(setitimer_which),
	.sanitise = sanitise_setitimer,
	.rettype = RET_ZERO_SUCCESS,
};
