/*
 * Sequence-aware fuzzing — Phase 1 chain executor.
 *
 * Dispatches a short chain of random syscalls per fuzzer iteration and
 * threads each call's return value into the next call's args with a
 * tunable probability.  No persistence between iterations: each chain
 * is freshly randomised, executed, and discarded.  Phase 2 will mine
 * productive chains into a corpus; Phase 3 will add resource-type
 * dependency tracking.  Keeping the Phase 1 surface narrow makes it
 * cheap to revert if the measurement comes back negative.
 *
 * Chain length is drawn from a geometric distribution biased toward 2:
 * P(2)=50%, P(3)=30%, P(4)=20%.  The bias toward 2 is deliberate —
 * most setup-then-use kernel paths fit in two calls (open then ioctl,
 * socket then sendmsg), and shorter chains preserve fuzzer throughput
 * while still exercising the longer-tail patterns at lower frequency.
 *
 * Substitution-vs-failure: if a step's retval is negative (errno-style
 * failure) the next step is dispatched without a substitute, since
 * passing -EBADF as an fd to the following call wastes the slot.  The
 * chain itself continues — a single mid-chain failure does not abort
 * the remaining steps.
 */

#include <stdlib.h>

#include "child.h"
#include "minicorpus.h"
#include "random.h"
#include "sequence.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"

#if ENABLE_SEQUENCE_CHAIN

static unsigned int pick_chain_length(void)
{
	unsigned int r = rand() % 10;

	if (r < 5)
		return 2;
	if (r < 8)
		return 3;
	return 4;
}

bool run_sequence_chain(struct childdata *child)
{
	unsigned int len, i;
	bool have_substitute = false;
	unsigned long substitute_retval = 0;

	len = pick_chain_length();

	for (i = 0; i < len; i++) {
		bool step_ret;
		unsigned long rv;

		step_ret = random_syscall_step(child, have_substitute,
					       substitute_retval);
		if (step_ret == FAIL)
			return FAIL;

		/* Decide whether the next step may receive a substitute.
		 * Errno-style returns (-1..-4095 region, all negative when
		 * read as long) are dropped because they are unlikely to
		 * be useful as downstream arg values.  Zero is allowed
		 * through — RET_ZERO_SUCCESS calls return 0 on success
		 * and a NULL substituted into a pointer slot is a useful
		 * boundary case to exercise. */
		rv = child->syscall.retval;
		if ((long)rv < 0) {
			have_substitute = false;
			substitute_retval = 0;
		} else {
			have_substitute = true;
			substitute_retval = rv;
		}
	}

	if (minicorpus_shm != NULL)
		__atomic_fetch_add(&minicorpus_shm->chain_iter_count, 1,
				   __ATOMIC_RELAXED);

	return true;
}

#else /* !ENABLE_SEQUENCE_CHAIN */

bool run_sequence_chain(struct childdata *child)
{
	return random_syscall(child);
}

#endif
