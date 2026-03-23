/*
 * SYSCALL_DEFINE2(sched_setparam, pid_t, pid, struct sched_param __user *, param)
 */
#include <sched.h>
#include "random.h"
#include "sanitise.h"

static void sanitise_sched_setparam(struct syscallrecord *rec)
{
	struct sched_param *sp;

	sp = (struct sched_param *) get_writable_address(sizeof(*sp));

	switch (rand() % 4) {
	case 0: sp->sched_priority = 0; break;			/* SCHED_OTHER/BATCH/IDLE */
	case 1: sp->sched_priority = 1; break;			/* minimum RT */
	case 2: sp->sched_priority = 99; break;			/* maximum RT */
	default: sp->sched_priority = rand() % 100; break;	/* random valid */
	}

	rec->a2 = (unsigned long) sp;
}

struct syscallentry syscall_sched_setparam = {
	.name = "sched_setparam",
	.group = GROUP_SCHED,
	.num_args = 2,
	.arg1name = "pid",
	.arg1type = ARG_PID,
	.arg2name = "param",
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_sched_setparam,
};
