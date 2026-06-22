/*
 * SYSCALL_DEFINE3(sched_setscheduler, pid_t, pid, int, policy, struct sched_param __user *, param)
 */
#include <sched.h>
#include "compat.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

static unsigned long sched_setscheduler_policies[] = {
	SCHED_OTHER, SCHED_FIFO, SCHED_RR, SCHED_BATCH,
	SCHED_IDLE, SCHED_DEADLINE,
};

static void sanitise_sched_setscheduler(struct syscallrecord *rec)
{
	struct sched_param *sp;
	unsigned int roll;
	int policy;

	sp = (struct sched_param *) get_writable_address(sizeof(*sp));
	if (sp == NULL)
		return;

	/*
	 * Policy was already chosen by ARG_OP / ARGLIST into rec->a2 by
	 * generic_sanitise().  Read it so the priority shape can match the
	 * policy's legality rules instead of being drawn independently:
	 * SCHED_OTHER/BATCH/IDLE accept only priority == 0; SCHED_FIFO/RR
	 * accept 1..99; SCHED_DEADLINE cannot be set via setscheduler at
	 * all (the kernel returns -EINVAL -- DEADLINE has to go through
	 * sched_setattr), so priority is irrelevant on that path.
	 */
	policy = (int) rec->a2;
	roll = rnd_modulo_u32(100);

	if (roll < 70) {
		/* Valid shape: priority matches policy. */
		switch (policy) {
		case SCHED_FIFO:
		case SCHED_RR:
			sp->sched_priority = (int) (1 + rnd_modulo_u32(99));
			break;
		default:
			sp->sched_priority = 0;
			break;
		}
	} else if (roll < 90) {
		/*
		 * Real policy + invalid one-field: keep the kernel's
		 * validation paths warm.  RT policies with priority == 0
		 * or > 99, non-RT policies with a non-zero priority --
		 * both shapes the kernel must reject.
		 */
		switch (policy) {
		case SCHED_FIFO:
		case SCHED_RR:
			if (RAND_BOOL())
				sp->sched_priority = 0;
			else
				sp->sched_priority =
					(int) (100 + rnd_modulo_u32(100));
			break;
		default:
			sp->sched_priority =
				(int) (1 + rnd_modulo_u32(99));
			break;
		}
	} else {
		/* 10% fully random for the long tail. */
		sp->sched_priority = (int) rnd_modulo_u32(256);
	}

	/* Target self (0) most of the time.  ARG_PID overwhelmingly draws
	 * pool/random pids the kernel EPERMs without CAP_SYS_NICE, and a
	 * sched_setscheduler that bounces on permission never reaches the
	 * policy/priority validator -- bias toward the one pid where the
	 * set actually lands. */
	if (rnd_modulo_u32(100) < 70)
		rec->a1 = 0;

	rec->a3 = (unsigned long) sp;
	avoid_shared_buffer_inout(&rec->a3, sizeof(*sp));
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
