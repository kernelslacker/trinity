/*
 * SHADOW counterfactual-attribution classifier.
 *
 * Fires from cmp_hints_feedback_credit_pc()'s outcome_win arm before
 * the per-child consumed-stash reset -- i.e. the "hint consumed AND
 * new PC edge" precondition the design keys off.  Each stash entry
 * the credit drain is about to walk is one cfactual candidate.  For
 * every candidate, the classifier drives an A/B replay: dispatch S
 * again with fresh args EXCEPT the hint's slot pinned to a control
 * value that fails the compare at cmp_ip, then read the inner call's
 * new-PC-edge signal to split:
 *
 *   inner_new_edges == false -- the parent's new edge required the
 *       hint; credit cmp_hint_cfactual_win (the causal true-positive
 *       count the arm-promotion gate consumes).
 *   inner_new_edges == true  -- the parent's new edge would have
 *       appeared regardless; credit cmp_hint_cfactual_coincidence.
 *       This is the lane the 0.0064% correlational counter silently
 *       miscredits.
 *   replay did NOT run (destructive/AVOID_REEXEC/validate-silent/
 *       slot-bounds/window-cap gate fired inside the harness, or the
 *       candidate carried no slot to pin) -- credit
 *       cmp_hint_cfactual_flaky (accounting denominator lost to
 *       replay noise + harness gates; explicitly OUTSIDE the promotion
 *       ratio per the design's "absent in both is replay-flaky, never
 *       a win" rule).
 *
 * Shared-tier quarantine.  A stash entry stamped served_from_shared=1
 * (COMBINED-mode shared-tier serve) routes to
 * cmp_hint_cfactual_shared_quarantined and skips the replay entirely
 * -- the shared-tier serve does not carry an arg_idx that would let
 * us target the pin, and the whole point of the quarantine is that a
 * cross-syscall-observed value must not credit the native-pool causal
 * accounting either way.  Mirror of the credit-drain's shared-tier
 * quarantine already established in cmp_hints/credit.c.
 *
 * Live behaviour is unchanged: no injection / eviction / ranking path
 * reads cmp_cfactual_mode or any of the four cfactual counters, and
 * no cfactual outcome routes back into the per-entry wins/misses the
 * live pick would weigh by.  OFF is byte-for-byte identical to a pre-
 * row build under a fixed-seed --dry-run.  SHADOW consumes RNG on the
 * replay path (generate_syscall_args -> pin) -- that is the whole
 * point of the mode and matches the byte-identity discipline the
 * scaffold commit spelled out (byte-identity is required ONLY under
 * OFF; SHADOW is an opt-in measurement mode).
 */

#include <stdint.h>

#include "child.h"
#include "cmp_hints.h"
#include "kcov.h"
#include "shm.h"

/*
 * Mask a raw operand value to the recorded comparison width.  Width
 * comes from the stash entry's `size` field (bytes: 1/2/4/8); the
 * caller has already gated bad-width entries into flaky before
 * reaching the compute step, but the switch defaults to the full
 * unsigned long width as a defence-in-depth against a torn stash.
 */
static unsigned long cfactual_width_mask(unsigned int size)
{
	switch (size) {
	case 1: return 0xffUL;
	case 2: return 0xffffUL;
	case 4: return 0xffffffffUL;
	case 8:
	default:
		return ~0UL;
	}
}

/*
 * Compute the control value: invert the matched bits of v within the
 * recorded width.  Guaranteed to differ from v: mask is a run of low
 * bits, and (~v & mask) == (v & mask) would require v & mask == ~v &
 * mask, i.e. every masked bit both set and clear, contradiction.  For
 * a "nonconst / unknown operand" the design allows a fresh random-at-
 * width, but the raw pool stashes only known constants so the invert-
 * bits path is complete for the stash we walk.
 */
static unsigned long cfactual_control_value(unsigned long value,
					    unsigned int size)
{
	unsigned long mask = cfactual_width_mask(size);

	return (~value) & mask;
}

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
	 * same clamp implicitly via its bounded loop, but here the bound
	 * protects the classifier bumps against an untrusted count.
	 */
	if (n > CMP_HINT_CONSUMED_STASH_MAX)
		n = CMP_HINT_CONSUMED_STASH_MAX;

	for (i = 0; i < n; i++) {
		const struct cmp_hint_consumed_entry *e =
			&child->cmp_hints_consumed_stash[i];
		unsigned long control_value;
		bool inner_new_edges = false;
		bool replay_ran;

		/*
		 * Shared-tier quarantine -- mirror of the credit_pc
		 * served_from_shared branch in cmp_hints/credit.c.  A
		 * shared-served candidate carries no arg_idx and its
		 * cmp_ip is a cross-syscall observation; it must not
		 * pollute the native win / coincidence / flaky tallies.
		 */
		if (e->served_from_shared) {
			__atomic_fetch_add(
				&kcov_shm->cmp_hint_cfactual_shared_quarantined,
				1UL, __ATOMIC_RELAXED);
			continue;
		}

		/*
		 * Only the per-syscall pool lane is wired for cfactual
		 * replay today: the field-pool pin path
		 * (REEXEC_FIELD_TIMESPEC_{SEC,NSEC}) is a follow-up unit
		 * that will grow the harness surface -- routing field-
		 * pool candidates through the scalar-slot harness would
		 * pin the STRUCT-pointer arg to control_value and dodge
		 * the compare entirely, misclassifying every field-pool
		 * candidate as a win.  Route these to flaky (accounting
		 * denominator lost to harness coverage gap, not a causal
		 * signal).
		 */
		if (e->pool_kind != CMP_HINT_POOL_PER_SYSCALL) {
			__atomic_fetch_add(&kcov_shm->cmp_hint_cfactual_flaky,
					   1UL, __ATOMIC_RELAXED);
			continue;
		}

		/*
		 * arg_idx == 0 means the try_get caller did not identify
		 * an arg slot for this pull.  Without a slot to pin the
		 * replay cannot form a coherent control -- route to flaky.
		 */
		if (e->arg_idx == 0 || e->arg_idx > 6) {
			__atomic_fetch_add(&kcov_shm->cmp_hint_cfactual_flaky,
					   1UL, __ATOMIC_RELAXED);
			continue;
		}

		/*
		 * Bad width in the stash (size not in {1,2,4,8}) means
		 * the mask computation would fall through to full-word
		 * and the control value might not defeat the kernel-side
		 * width-narrowed compare.  Discard rather than mis-count.
		 */
		if (e->size != 1 && e->size != 2 && e->size != 4 &&
		    e->size != 8) {
			__atomic_fetch_add(&kcov_shm->cmp_hint_cfactual_flaky,
					   1UL, __ATOMIC_RELAXED);
			continue;
		}

		control_value = cfactual_control_value(e->value, e->size);

		replay_ran = cmp_hints_cfactual_replay_with_pin(
			child, e->arg_idx, control_value, &inner_new_edges);

		if (!replay_ran) {
			__atomic_fetch_add(&kcov_shm->cmp_hint_cfactual_flaky,
					   1UL, __ATOMIC_RELAXED);
			continue;
		}

		/*
		 * The parent produced new edges by construction (capture
		 * fires on credit_pc(win)).  The classifier reads the
		 * inner call's new-edges signal:
		 *   inner_new_edges  -> COINCIDENCE (edge would have
		 *       appeared without the hint; the parent's win was
		 *       riding along with the coverage, not caused by
		 *       the injected value)
		 *   !inner_new_edges -> WIN (the hint was necessary to
		 *       open the parent's new edge)
		 *
		 * The design's "control diverged before reaching cmp_ip
		 * -> discard" case cannot be directly verified on a PC-
		 * mode child (cmp_ip hits are visible only via CMP-mode
		 * kcov, and this arm is PC-mode by construction).  A
		 * divergent control that follows a different in-kernel
		 * path will typically ALSO produce new edges of its own
		 * and land in coincidence -- the honest accounting per
		 * the design's replay-noise caveat.
		 */
		if (inner_new_edges)
			__atomic_fetch_add(
				&kcov_shm->cmp_hint_cfactual_coincidence,
				1UL, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->cmp_hint_cfactual_win,
					   1UL, __ATOMIC_RELAXED);
	}
}
