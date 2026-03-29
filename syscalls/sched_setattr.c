/*
 * SYSCALL_DEFINE3(sched_setattr, pid_t, pid, struct sched_attr __user *, uattr,
 *		   unsigned int, flags)
 */
#include <linux/sched/types.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"
#include "compat.h"

static void sanitise_sched_setattr(struct syscallrecord *rec)
{
	struct sched_attr *sa;

	sa = (struct sched_attr *) get_writable_address(sizeof(*sa));
	memset(sa, 0, sizeof(*sa));

	sa->size = sizeof(*sa);

	switch (rand() % 6) {
	case 0: /* SCHED_OTHER */
		sa->sched_policy = 0;
		sa->sched_nice = (rand() % 40) - 20;	/* -20 to 19 */
		break;
	case 1: /* SCHED_FIFO */
		sa->sched_policy = 1;
		sa->sched_priority = 1 + (rand() % 99);
		break;
	case 2: /* SCHED_RR */
		sa->sched_policy = 2;
		sa->sched_priority = 1 + (rand() % 99);
		break;
	case 3: /* SCHED_BATCH */
		sa->sched_policy = 3;
		sa->sched_nice = (rand() % 40) - 20;
		break;
	case 4: /* SCHED_IDLE */
		sa->sched_policy = SCHED_IDLE;
		break;
	default: /* SCHED_DEADLINE */
		sa->sched_policy = SCHED_DEADLINE;
		sa->sched_runtime  = 1000000ULL * (1 + (rand() % 10));	/* 1-10ms */
		sa->sched_deadline = sa->sched_runtime * (1 + (rand() % 5));
		sa->sched_period   = sa->sched_deadline * (1 + (rand() % 3));
		break;
	}

	rec->a2 = (unsigned long) sa;
	rec->a3 = 0;	/* flags must be zero */
}

struct syscallentry syscall_sched_setattr = {
	.name = "sched_setattr",
	.group = GROUP_SCHED,
	.num_args = 3,
	.argtype = { [0] = ARG_PID },
	.argname = { [0] = "pid", [1] = "uattr", [2] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_sched_setattr,
};
