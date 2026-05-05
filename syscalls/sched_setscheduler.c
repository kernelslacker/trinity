/*
 * SYSCALL_DEFINE3(sched_setscheduler, pid_t, pid, int, policy, struct sched_param __user *, param)
 */
#include <sched.h>
#include "compat.h"
#include "random.h"
#include "sanitise.h"

static unsigned long sched_setscheduler_policies[] = {
	SCHED_OTHER, SCHED_FIFO, SCHED_RR, SCHED_BATCH,
	SCHED_IDLE, SCHED_DEADLINE,
};

static void sanitise_sched_setscheduler(struct syscallrecord *rec)
{
	struct sched_param *sp;

	sp = (struct sched_param *) get_writable_address(sizeof(*sp));

	switch (rand() % 4) {
	case 0: sp->sched_priority = 0; break;			/* SCHED_OTHER/BATCH/IDLE */
	case 1: sp->sched_priority = 1; break;			/* minimum RT */
	case 2: sp->sched_priority = 99; break;			/* maximum RT */
	default: sp->sched_priority = rand() % 100; break;	/* random valid */
	}

	rec->a3 = (unsigned long) sp;
}

struct syscallentry syscall_sched_setscheduler = {
	.name = "sched_setscheduler",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_SCHED,
	.num_args = 3,
	.argtype = { [0] = ARG_PID, [1] = ARG_OP, [2] = ARG_ADDRESS },
	.argname = { [0] = "pid", [1] = "policy", [2] = "param" },
	.arg_params[1].list = ARGLIST(sched_setscheduler_policies),
	.sanitise = sanitise_sched_setscheduler,
};
