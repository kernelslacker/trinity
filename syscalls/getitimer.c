/*
 * SYSCALL_DEFINE2(getitimer, int, which, struct itimerval __user *, value)
 */
#include <sys/time.h>
#include "sanitise.h"

static unsigned long getitimer_which[] = {
	ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF,
};

static void sanitise_getitimer(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, sizeof(struct itimerval));
}

struct syscallentry syscall_getitimer = {
	.name = "getitimer",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "which", [1] = "value" },
	.arg_params[0].list = ARGLIST(getitimer_which),
	.sanitise = sanitise_getitimer,
	.rettype = RET_ZERO_SUCCESS,
};
