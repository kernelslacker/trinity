/*
 * SYSCALL_DEFINE1(sched_get_priority_max, int, policy)
 */
#include <sched.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

static unsigned long sched_policies[] = {
	SCHED_OTHER, SCHED_FIFO, SCHED_RR,
	SCHED_BATCH, SCHED_IDLE, SCHED_DEADLINE,
};

/*
 * Oracle: sys_sched_get_priority_max returns a static well-known value
 * per scheduling-policy enum baked into the scheduler core:
 *
 *   SCHED_OTHER / SCHED_BATCH / SCHED_IDLE / SCHED_DEADLINE -> 0
 *   SCHED_FIFO / SCHED_RR                                   -> 99 (MAX_RT_PRIO-1)
 *
 * These constants are part of the userspace ABI -- libc, glibc's
 * pthread realtime helpers, runtimes (Java, Go, Erlang) and countless
 * applications hard-code the SCHED_FIFO/SCHED_RR bound at 99 and the
 * normal-policy bound at 0.  Any silent kernel re-mapping (e.g. a
 * refactor that mis-orders the policy switch in sched/syscalls.c, a
 * new policy slotted into the wrong arm, or a torn read of the
 * policy enum) would break those consumers.  Hard-code the expected
 * value per policy so we catch divergence the moment it appears.
 *
 * Skip if the kernel rejected the policy with -EINVAL: there is no
 * answer to validate.  Only oracle the well-known stable policies;
 * SCHED_EXT (7) and any future policy fall through silently rather
 * than false-positive on values we do not have a hardcoded
 * expectation for.  Sample one in a hundred to stay in line with the
 * rest of the oracle family.
 */
static void post_sched_get_priority_max(struct syscallrecord *rec)
{
	int got, expected;

	if (!ONE_IN(100))
		return;
	if ((int) rec->retval == -1)
		return;

	switch ((int) rec->a1) {
	case SCHED_OTHER:
		expected = 0;
		break;
	case SCHED_FIFO:
		expected = 99;
		break;
	case SCHED_RR:
		expected = 99;
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
	default:
		return;
	}

	got = (int) rec->retval;
	if (got != expected) {
		output(0, "sched_get_priority_max oracle: policy=%d returned %d but expected %d\n",
		       (int) rec->a1, got, expected);
		__atomic_add_fetch(&shm->stats.sched_get_priority_max_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_sched_get_priority_max = {
	.name = "sched_get_priority_max",
	.group = GROUP_SCHED,
	.num_args = 1,
	.argtype = { [0] = ARG_OP },
	.argname = { [0] = "policy" },
	.arg_params[0].list = ARGLIST(sched_policies),
	.post = post_sched_get_priority_max,
};
