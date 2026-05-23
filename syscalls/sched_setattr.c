/*
 * SYSCALL_DEFINE3(sched_setattr, pid_t, pid, struct sched_attr __user *, uattr,
 *		   unsigned int, flags)
 */
#include <linux/sched/types.h>
#include <string.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "compat.h"

static void sanitise_sched_setattr(struct syscallrecord *rec)
{
	struct sched_attr *sa;
	unsigned int roll;

	sa = (struct sched_attr *) get_writable_struct(sizeof(*sa));
	if (!sa)
		return;
	memset(sa, 0, sizeof(*sa));

	/*
	 * sa->size is the kernel's ABI version tag for struct sched_attr;
	 * a wrong size short-circuits the validator before any policy /
	 * priority / deadline param gets inspected.  Keep it correct so
	 * the enriched value distribution below actually reaches the
	 * per-policy legality logic instead of bouncing on -E2BIG.
	 */
	sa->size = sizeof(*sa);

	roll = rnd_modulo_u32(100);

	if (roll < 70) {
		/* Valid shape bucket: policy + matching params. */
		switch (rnd_modulo_u32(6)) {
		case 0: /* SCHED_OTHER */
			sa->sched_policy = 0;
			sa->sched_nice = (rnd_modulo_u32(40)) - 20;	/* -20 to 19 */
			break;
		case 1: /* SCHED_FIFO */
			sa->sched_policy = 1;
			sa->sched_priority = 1 + (rnd_modulo_u32(99));
			break;
		case 2: /* SCHED_RR */
			sa->sched_policy = 2;
			sa->sched_priority = 1 + (rnd_modulo_u32(99));
			break;
		case 3: /* SCHED_BATCH */
			sa->sched_policy = 3;
			sa->sched_nice = (rnd_modulo_u32(40)) - 20;
			break;
		case 4: /* SCHED_IDLE */
			sa->sched_policy = SCHED_IDLE;
			break;
		default: /* SCHED_DEADLINE */
			sa->sched_policy = SCHED_DEADLINE;
			sa->sched_runtime  = 1000000ULL * (1 + (rnd_modulo_u32(10)));	/* 1-10ms */
			sa->sched_deadline = sa->sched_runtime * (1 + (rnd_modulo_u32(5)));
			sa->sched_period   = sa->sched_deadline * (1 + (rnd_modulo_u32(3)));
			break;
		}
	} else if (roll < 90) {
		/*
		 * Invalid-one-field bucket: real policy, one field outside
		 * legality.  Keeps the per-policy validation paths warm
		 * without the policy field itself being random garbage.
		 */
		switch (rnd_modulo_u32(6)) {
		case 0: /* SCHED_OTHER with non-zero priority */
			sa->sched_policy = 0;
			sa->sched_priority = 1 + rnd_modulo_u32(99);
			break;
		case 1: /* SCHED_FIFO with priority == 0 or > 99 */
			sa->sched_policy = 1;
			sa->sched_priority = RAND_BOOL() ? 0 :
				(100 + rnd_modulo_u32(100));
			break;
		case 2: /* SCHED_RR with priority == 0 or > 99 */
			sa->sched_policy = 2;
			sa->sched_priority = RAND_BOOL() ? 0 :
				(100 + rnd_modulo_u32(100));
			break;
		case 3: /* SCHED_BATCH with nice outside [-20, 19] */
			sa->sched_policy = 3;
			sa->sched_nice = 50;
			break;
		case 4: /* SCHED_IDLE with non-zero priority */
			sa->sched_policy = SCHED_IDLE;
			sa->sched_priority = 1 + rnd_modulo_u32(99);
			break;
		default: /* SCHED_DEADLINE with deadline < runtime */
			sa->sched_policy = SCHED_DEADLINE;
			sa->sched_runtime  = 10000000ULL;
			sa->sched_deadline = 1000000ULL;
			sa->sched_period   = 100000000ULL;
			break;
		}
	} else {
		/*
		 * 10%: fully random payload (size still correct so the
		 * validator engages).  Hits the long-tail combinations the
		 * structured buckets above never produce.
		 */
		sa->sched_policy = rnd_u32() & 0xff;
		sa->sched_priority = rnd_u32() & 0xff;
		sa->sched_nice = (int) rnd_modulo_u32(80) - 40;
		sa->sched_runtime  = rnd_u64();
		sa->sched_deadline = rnd_u64();
		sa->sched_period   = rnd_u64();
		sa->sched_flags    = rnd_u64();
	}

	rec->a2 = (unsigned long) sa;
	avoid_shared_buffer_inout(&rec->a2, sizeof(struct sched_attr));
	rec->a3 = 0;	/* flags must be zero */

	/* Target self (0) most of the time.  ARG_PID overwhelmingly draws
	 * pool/random pids the kernel EPERMs without CAP_SYS_NICE, so the
	 * set never reaches the legality validator -- bias toward the one
	 * pid where the set actually lands. */
	if (rnd_modulo_u32(100) < 70)
		rec->a1 = 0;
}

struct syscallentry syscall_sched_setattr = {
	.name = "sched_setattr",
	.group = GROUP_SCHED,
	.num_args = 3,
	.argtype = { [0] = ARG_PID, [1] = ARG_STRUCT_PTR_IN },
	.argname = { [0] = "pid", [1] = "uattr", [2] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_sched_setattr,
};
