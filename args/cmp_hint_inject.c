#include <stdbool.h>
#include <stdint.h>

#include "args-internal.h"
#include "child.h"
#include "cmp_hints.h"
#include "kcov.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "strategy.h"	// plateau_rescue_bias_active_for, RRC_CMP_DERIVED
#include "syscall.h"

/*
 * CMP-hint injection rate.  Baseline is per-call-site (1-in-16 for the
 * ARG_OP / ARG_LIST paths, 1-in-9 for the ARG_UNDEFINED case-0 hint
 * shortcut, 1-in-10 for the ARG_STRUCT_SIZE fallback); boosted to
 * 1-in-4 inside (a) a SR_PLATEAU_FORCE intervention whose dominant
 * rescue class is RRC_CMP_DERIVED, or (b) any plateau window the
 * parent's hypothesis tick has classified as CMP_RISING_PC_FLAT.
 * (b) bypasses the three-gate RRC_CMP_DERIVED chain: the diagnostic
 * has already concluded the kernel is emitting unique CMP signal we
 * are failing to convert, so inject more aggressively even when the
 * rotation hasn't landed on the CMP_DERIVED amplification slot.
 * Wrapped in a helper so any future tuning lands in one place rather
 * than scattered across the five call sites.
 */
#define CMP_HINT_INJECT_DENOM_BASELINE  16U
#define CMP_HINT_INJECT_DENOM_AMPLIFIED 4U
/* Arm B baseline denom for the per-child A/B comparison wired through
 * cmp_hint_baseline_should_inject() below.  Arm A children keep the
 * historical 1-in-16 baseline; Arm B children swap to 1-in-12 -- a
 * modestly higher inject rate that the row measures against the
 * existing PC-edge yield counters.  Kept narrow on purpose: the band
 * here is tight, too-aggressive injection starves the random arms.
 * The AMPLIFIED denom (4U) is the separate plateau-driven lever and is
 * left at its current value -- the A/B knob only moves the baseline. */
#define CMP_HINT_INJECT_DENOM_BASELINE_ARM_B 12U
/* lcm(16, 12) -- the smallest sample period that lets one uniform roll
 * answer both denoms exactly: Arm A fires iff sample % 16 == 0, Arm B
 * fires iff sample % 12 == 0.  Used only on the Arm B path inside
 * cmp_hint_baseline_should_inject() to count per-call divergence
 * without perturbing Arm A's per-call RNG sequence. */
#define CMP_HINT_INJECT_BASELINE_LCM    48U

unsigned int cmp_hint_inject_denom(unsigned int baseline)
{
	if (__atomic_load_n(&shm->plateau_current_hypothesis,
			    __ATOMIC_RELAXED) ==
	    (int)PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT)
		return CMP_HINT_INJECT_DENOM_AMPLIFIED;
	if (plateau_rescue_bias_active_for(RRC_CMP_DERIVED))
		return CMP_HINT_INJECT_DENOM_AMPLIFIED;
	return baseline;
}

/*
 * Per-child A/B-gated baseline cmp-hint inject decision.
 *
 * Replaces the bare ONE_IN(cmp_hint_inject_denom(CMP_HINT_INJECT_DENOM_BASELINE))
 * gate at each of the three BASELINE callsites in this file (ARG_RANGE,
 * ARG_OP, ARG_LIST).  The AMPLIFIED callsites at gen_undefined_arg
 * (denom 9) and the ARG_STRUCT_SIZE fallback (denom 10) are out of
 * scope by design and continue to call cmp_hint_inject_denom() directly.
 *
 * Behaviour summary:
 *  - When cmp_hint_inject_denom() returns AMPLIFIED (plateau path),
 *    both arms use the amplified denom byte-identically; the A/B knob
 *    is silent under amplification.
 *  - When the resolved denom is the baseline (16) AND the child is
 *    stamped Arm B (child->cmp_hint_inject_arm_b == true), we swap to
 *    ONE_IN(12), bump cmp_inject_arm_b_baseline_fires on a fire, and
 *    bump cmp_inject_denom_diverged when the same uniform sample would
 *    have produced a different decision under Arm A's denom.
 *  - Arm A children, parent-context callers (this_child() == NULL),
 *    and the amplified path all preserve the historical sequence:
 *    exactly one ONE_IN(denom) call, no extra RNG consumption.
 *
 * The per-call divergence counter is intentionally Arm-B-only so that
 * Arm A's children remain byte-identical to the pre-row build.  The
 * counter is therefore a lower bound on the cross-arm divergence: it
 * counts ~half the fleet's "Arm A would have decided otherwise" events,
 * which is enough to size the A/B effect without giving up arm-A
 * purity.
 */
bool cmp_hint_baseline_should_inject(void)
{
	unsigned int denom = cmp_hint_inject_denom(CMP_HINT_INJECT_DENOM_BASELINE);
	struct childdata *child;
	bool fires;

	if (denom != CMP_HINT_INJECT_DENOM_BASELINE)
		return ONE_IN(denom);

	child = this_child();
	if (child == NULL || !child->cmp_hint_inject_arm_b) {
		fires = ONE_IN(denom);
		if (fires && kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cohorts.cmp_inject_arm_a_baseline_fires,
					   1UL, __ATOMIC_RELAXED);
		return fires;
	}

	{
		unsigned int sample = rnd_modulo_u32(CMP_HINT_INJECT_BASELINE_LCM);
		bool arm_a_fires = (sample % CMP_HINT_INJECT_DENOM_BASELINE) == 0;
		bool arm_b_fires = (sample % CMP_HINT_INJECT_DENOM_BASELINE_ARM_B) == 0;

		if (kcov_shm != NULL && arm_a_fires != arm_b_fires)
			__atomic_fetch_add(&kcov_shm->cohorts.cmp_inject_denom_diverged,
					   1UL, __ATOMIC_RELAXED);
		if (kcov_shm != NULL && arm_b_fires)
			__atomic_fetch_add(&kcov_shm->cohorts.cmp_inject_arm_b_baseline_fires,
					   1UL, __ATOMIC_RELAXED);
		return arm_b_fires;
	}
}

/*
 * bookkeeping for a committed cmp_hint injection.
 *
 * Called from each of the five argtype-handler callsites that pull a
 * cmp_hints_try_get() hint and commit it to a produced syscall arg.
 * Centralised so the observability counters stay in lock-step: any new
 * injection callsite gets the full row of bumps via a single helper
 * call instead of three open-coded atomics.  Effects:
 *  - bumps the existing flat cmp_hints_injected counter so the legacy
 *    consumers (periodic dump, JSON dump) keep working unchanged;
 *  - bumps the per-nr per_syscall_cmp_injected[rec->nr] partition that
 *    pairs with per_syscall_cmp_attempts / _returned at the producer
 *    side;
 *  - bumps the per-callsite bucket counter so the "which argtype
 *    handler is responsible for the bulk of injections" question is
 *    answerable from the same dump;
 *  - sets the per-child cmp_hint_injected_this_call latch that
 *    kcov_collect()'s found_new branch reads to attribute a PC-edge
 *    win to the cmp-hint pipeline.
 */
void credit_cmp_hint_injection(struct syscallrecord *rec,
			       enum cmp_hint_callsite callsite)
{
	struct childdata *child;

	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->hints_flat.cmp_hints_injected,
				   1UL, __ATOMIC_RELAXED);
		if (rec->nr < MAX_NR_SYSCALL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hint_ps.per_syscall_cmp_injected[rec->nr],
				1UL, __ATOMIC_RELAXED);
		if ((unsigned int)callsite < (unsigned int)CMP_HINT_CALLSITE_NR)
			__atomic_fetch_add(
				&kcov_shm->cmp_hint_callsite_injected[callsite],
				1UL, __ATOMIC_RELAXED);
	}

	/* Per-call latch: read in kcov_collect()'s found_new branch.
	 * generate_syscall_args() clears the flag at the top of each new
	 * call, so a stale true from a prior call cannot survive.  Parent-
	 * context this_child()==NULL is benign: the flag has no parent-side
	 * consumer, so the helper is a quiet no-op in that path. */
	child = this_child();
	if (child != NULL)
		child->cmp_hint_injected_this_call = true;
}
