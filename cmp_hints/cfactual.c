/*
 * SHADOW counterfactual-attribution scaffold.
 *
 * Consumes the per-child cmp_hints_consumed_stash immediately before the
 * credit-drain resets it, treating each stash entry drained under a
 * PC-mode win as one cfactual candidate.  The three cfactual outcome
 * counters (cmp_hint_cfactual_win / _coincidence / _flaky) are shm
 * scalars on struct kcov_shared; see the header comment on
 * cmp_hint_cfactual_win in include/kcov.h for the classifier contract
 * and the shadow-to-live promotion gate the counters serve.
 *
 * This TU owns the candidate-capture site and the mode-gate short
 * circuit.  The actual A/B control-replay (regenerate S with the hint
 * slot pinned to an inverted-bits control value that fails the compare
 * at cmp_ip, confirm cmp_ip is still hit in the control run, compare
 * per-dispatch coverage delta with vs without the hint) reuses the same
 * reexec-with-pin infrastructure the arg-perturbation minicorpus lane
 * uses and lands in a follow-up unit (256·A tie-in: ONE shared harness,
 * two consumers).  Until then every captured candidate routes to
 * cmp_hint_cfactual_flaky -- the honest "no attribution possible /
 * harness unavailable" lane -- so the mode gate + observability
 * plumbing settle before the harness swap-in.
 *
 * Live behaviour is unchanged in either mode: no injection / eviction /
 * ranking path consults cmp_cfactual_mode or reads any of the three
 * counters, and the consumed-stash is not mutated -- the caller's post-
 * hook reset owns the stash lifecycle.
 */

#include <stdint.h>

#include "child.h"
#include "cmp_hints.h"
#include "kcov.h"
#include "shm.h"

void cmp_hints_cfactual_capture(struct childdata *child)
{
	unsigned int i, n;

	/*
	 * OFF short-circuit is the byte-identical-under-fixed-seed
	 * guarantee: no shm access, no per-child state read, no RNG
	 * consumption.  RELAXED load matches the discipline every other
	 * cmp-hints mode read (cmp_shared_tier_mode) uses on the hot path.
	 */
	if (__atomic_load_n(&cmp_cfactual_mode, __ATOMIC_RELAXED) ==
	    CMP_CFACTUAL_MODE_OFF)
		return;

	if (child == NULL)
		return;

	n = child->cmp_hints_consumed_count;
	if (n == 0)
		return;

	if (kcov_shm == NULL)
		return;

	/*
	 * Bound the walk against the compile-time stash cap in case a
	 * stomped counter reaches this call; the credit drain does the
	 * same clamp implicitly via its bounded loop, but here the
	 * bound protects the flaky-bump against an untrusted count.
	 */
	if (n > CMP_HINT_CONSUMED_STASH_MAX)
		n = CMP_HINT_CONSUMED_STASH_MAX;

	/*
	 * Follow-up harness will branch on the (nr, do32, cmp_ip, value,
	 * size, arg_idx) tuple stashed on each cmp_hint_consumed_entry
	 * and drive the control-replay classifier that partitions across
	 * the win / coincidence / flaky lanes.  Until it lands, every
	 * captured candidate is unclassifiable and lands here on flaky --
	 * the invariant is that the sum
	 *   cfactual_win + cfactual_coincidence + cfactual_flaky
	 * equals the total captured-candidate count, which today equals
	 * cfactual_flaky alone.
	 */
	for (i = 0; i < n; i++)
		__atomic_fetch_add(&kcov_shm->cmp_hint_cfactual_flaky, 1UL,
				   __ATOMIC_RELAXED);
}
