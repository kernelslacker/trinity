/*
 * SYSCALL_DEFINE1(sched_get_priority_min, int, policy)
 */
#include <sched.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

#include "kernel/sched.h"
static unsigned long sched_policies[] = {
	SCHED_OTHER, SCHED_FIFO, SCHED_RR,
	SCHED_BATCH, SCHED_IDLE, SCHED_DEADLINE,
	SCHED_EXT,
};

/*
 * Oracle: sys_sched_get_priority_min returns a static well-known value
 * per scheduling-policy enum baked into the scheduler core:
 *
 *   SCHED_OTHER / SCHED_BATCH / SCHED_IDLE / SCHED_DEADLINE -> 0
 *   SCHED_FIFO / SCHED_RR                                   -> 1
 *
 * These constants are part of the userspace ABI -- libc, glibc's
 * pthread realtime helpers, runtimes (Java, Go, Erlang) and countless
 * applications hard-code the SCHED_FIFO/SCHED_RR lower bound at 1 and
 * the normal-policy bound at 0.  Any silent kernel re-mapping (e.g. a
 * refactor that mis-orders the policy switch in sched/syscalls.c, a
 * new policy slotted into the wrong arm, or a torn read of the
 * policy enum) would break those consumers.  Hard-code the expected
 * value per policy so we catch divergence the moment it appears.
 *
 * Skip if the kernel rejected the policy with -EINVAL: there is no
 * answer to validate.  Only oracle the well-known stable policies;
 * any future policy falls through silently rather than false-positive
 * on values we do not have a hardcoded expectation for.  Sample one in
 * a hundred to stay in line with the rest of the oracle family.
 */
static void post_sched_get_priority_min(struct syscallrecord *rec)
{
	unsigned long retval = rec->retval;
	long ret = (long) retval;
	int got, expected, policy = (int) get_arg_snapshot(rec, 1);

	if (!ONE_IN(100))
		return;
	if ((int) ret == -1)
		return;

	switch (policy) {
	case SCHED_OTHER:
		expected = 0;
		break;
	case SCHED_FIFO:
		expected = 1;
		break;
	case SCHED_RR:
		expected = 1;
		break;
	case SCHED_BATCH:
		expected = 0;
		break;
	case SCHED_IDLE:
		expected = 0;
		break;
	case SCHED_DEADLINE:
		expected = 0;
		break;
	case SCHED_EXT:
		expected = 0;
		break;
	default:
		return;
	}

	got = (int) ret;
	if (got != expected) {
		output(0, "sched_get_priority_min oracle: policy=%d returned %d but expected %d\n",
		       policy, got, expected);
		__atomic_add_fetch(&shm->stats.oracle.sched_get_priority_min_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_sched_get_priority_min = {
	.name = "sched_get_priority_min",
	.group = GROUP_SCHED,
	.num_args = 1,
	.argtype = { [0] = ARG_OP },
	.argname = { [0] = "policy" },
	.arg_params[0].list = ARGLIST(sched_policies),
	.post = post_sched_get_priority_min,
	.rettype = RET_BORING,
	/* a1 (policy) drives post_sched_get_priority_min's switch -- it
	 * selects the scheduling policy whose well-known priority-min
	 * the returned value is bounded against, and is printed back in
	 * the mismatch diagnostic.  Shadow it so a sibling stomp between
	 * dispatch and post cannot swing the switch into a different
	 * case and mis-attribute the bound check against the wrong
	 * policy; mismatch bumps arg_shadow_stomp from inside
	 * get_arg_snapshot() and the handler still dispatches against
	 * the policy the kernel actually executed. */
	.arg_snapshot_mask = (1u << 0),
};
