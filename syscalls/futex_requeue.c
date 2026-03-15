/*
 * SYSCALL_DEFINE4(futex_requeue, struct futex_waitv __user *, waiters,
 *		unsigned int, flags, int, nr_wake, int, nr_requeue)
 */
#include "sanitise.h"

static void sanitise_futex_requeue(struct syscallrecord *rec)
{
	rec->a2 = 0;	/* no flags defined yet */
}

struct syscallentry syscall_futex_requeue = {
	.name = "futex_requeue",
	.num_args = 4,
	.arg1name = "waiters",
	.arg1type = ARG_ADDRESS,
	.arg2name = "flags",
	.arg3name = "nr_wake",
	.arg3type = ARG_RANGE,
	.low3range = 0,
	.hi3range = 128,
	.arg4name = "nr_requeue",
	.arg4type = ARG_RANGE,
	.low4range = 0,
	.hi4range = 128,
	.sanitise = sanitise_futex_requeue,
};
