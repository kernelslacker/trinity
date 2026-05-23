/*
 * SYSCALL_DEFINE2(sched_setparam, pid_t, pid, struct sched_param __user *, param)
 */
#include <sched.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

static void sanitise_sched_setparam(struct syscallrecord *rec)
{
	struct sched_param *sp;
	unsigned int roll;

	sp = (struct sched_param *) get_writable_struct(sizeof(*sp));
	if (!sp)
		return;

	/*
	 * sched_setparam takes no explicit policy, so the legal priority
	 * range depends on the target's current policy.  Bias toward 0
	 * because SCHED_OTHER (the default for fresh child processes)
	 * mandates priority == 0; keep an RT-priority slice for tasks
	 * that have already been promoted to SCHED_FIFO/RR, and a small
	 * invalid slice to keep the validator warm.
	 */
	roll = rnd_modulo_u32(100);
	if (roll < 70)
		sp->sched_priority = 0;
	else if (roll < 90)
		sp->sched_priority = (int) (1 + rnd_modulo_u32(99));
	else
		sp->sched_priority = (int) (100 + rnd_modulo_u32(100));

	/* Target self (0) most of the time so the assumed-policy bias
	 * lines up with the actual current policy of the running child. */
	if (rnd_modulo_u32(100) < 70)
		rec->a1 = 0;

	rec->a2 = (unsigned long) sp;
}

struct syscallentry syscall_sched_setparam = {
	.name = "sched_setparam",
	.group = GROUP_SCHED,
	.num_args = 2,
	.argtype = { [0] = ARG_PID },
	.argname = { [0] = "pid", [1] = "param" },
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_sched_setparam,
};
