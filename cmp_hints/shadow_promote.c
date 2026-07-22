/*
 * Shadow-arm promotion evaluator.  MEASURE-ONLY: nothing here writes
 * to a generation path, flips a live_flag, or nudges the pick
 * distribution.  On every stats-tick the evaluator walks a small
 * registry of shadow arms, snapshots each arm's baseline (would-
 * fire) and would-win counters out of kcov_shm, and if the promotion
 * criterion is met emits exactly one line to the stats stream so a
 * human can act on it.
 *
 * Rationale for the registry framing: cmp_hyp_bitmask_shadow_probe()
 * in cmp_hints/hyp.c already increments dedicated would_fire /
 * would_win pairs at the tail of struct kcov_shared for both the
 * FULL_OR and ANDNOT_TOGGLE lanes; those are the "would-win /
 * baseline-style counters" the pilot reuses verbatim.  The registry
 * table stores offsetof() locators into struct kcov_shared, and the
 * evaluator dereferences them via the runtime kcov_shm pointer, so
 * every walker (this evaluator, the surfacing rows in stats/dump.c,
 * and any future consumer) reads exactly the addresses the shadow
 * probe wrote in the child.  A future live counter for an arm is
 * plumbed by giving that arm a non-zero live_win_offset; the pilot
 * lanes have no live counterpart yet, so live_win_offset stays 0
 * for both entries.
 */

#include <stddef.h>

#include "kcov.h"
#include "shadow_promote.h"
#include "trinity.h"

/*
 * Named defaults for the pilot arms.  Referenced only by the arm
 * registry below -- the evaluator reads the per-arm fields, so a
 * future arm needing a stricter floor or threshold sets its own
 * initialiser values and neither of these constants moves.
 *
 * Baseline sample floor: below this many would-fire samples the
 * would-win / baseline ratio is dominated by short-run variance and
 * the surfacing line would fire spuriously on nearly-empty runs.
 * Sits at the low end of the 50-100 band this pilot targets.
 *
 * Would-win ratio threshold: per-mille integer to mirror the
 * surrounding kcov_coverage per_mille idiom and dodge floating-
 * point in the parent stats path.  120 / 1000 == 12%, middle of
 * the 10-15% band this pilot targets.  Per-mille (rather than
 * percent) so a future arm needing a finer threshold (e.g. 125)
 * can be described without changing the type.
 */
#define SHADOW_ARM_PILOT_MIN_BASELINE_SAMPLES 64UL
#define SHADOW_ARM_PILOT_WIN_RATIO_PER_MILLE  120UL

enum shadow_arm_id {
	SHADOW_ARM_CMP_WIDTH_PIN,
	SHADOW_ARM_CMP_HYP_POW2_DERIVE,
	SHADOW_ARM_CMP_HYP_BITMASK_FULL_OR,
	SHADOW_ARM_CMP_HYP_BITMASK_ANDNOT_TOGGLE,
	SHADOW_ARM_CMP_FIELD_SCOPED_INJECT,
	SHADOW_ARM_CMP_SHARED_TIER_COLDSERVE,
	SHADOW_ARM_NR,
};

static const struct shadow_arm shadow_arm_registry[SHADOW_ARM_NR] = {
	/*
	 * High-bit-preserving splice shadow, layered on the width-
	 * masked CMP RedQueen pin.  baseline bumps on every unique
	 * width-match stamp the live pin executes; would-win bumps
	 * on the subset where the matched slot has non-zero bits
	 * outside width_mask -- i.e. a splice replacement =
	 * (orig & ~width_mask) | (arg1 & width_mask) would produce
	 * a byte-different pin from today's whole-slot arg1
	 * overwrite.  No live counterpart yet.
	 */
	[SHADOW_ARM_CMP_WIDTH_PIN] = {
		.name = "cmp_width_pin_preserve",
		.would_win_offset =
			offsetof(struct kcov_shared,
				 cmp_width_pin_would_differ),
		.live_win_offset = 0,
		.baseline_offset =
			offsetof(struct kcov_shared,
				 cmp_width_pin_total),
		.live_flag = 0,
		.min_baseline_samples = SHADOW_ARM_PILOT_MIN_BASELINE_SAMPLES,
		.win_ratio_per_mille = SHADOW_ARM_PILOT_WIN_RATIO_PER_MILLE,
	},
	/*
	 * POW2 / alignment derive-class layered on the typed-
	 * hypothesis derive.  would_fire bumps on every eligible
	 * pick (argtype gate AND bit-pattern gate both open) --
	 * i.e. every derive where the class could plausibly emit a
	 * power-of-two or aligned candidate; would_win bumps on the
	 * subset where at least one candidate from {C>>1, C, C<<1,
	 * round-to-512, round-to-4096, round-to-page-size} differs
	 * from the value the live derive lane just emitted, i.e.
	 * the class would have contributed a value the existing
	 * lanes did not.  No live counterpart yet.
	 */
	[SHADOW_ARM_CMP_HYP_POW2_DERIVE] = {
		.name = "cmp_hyp_pow2_derive",
		.would_win_offset =
			offsetof(struct kcov_shared,
				 cmp_hyp_pow2_derive_would_win),
		.live_win_offset = 0,
		.baseline_offset =
			offsetof(struct kcov_shared,
				 cmp_hyp_pow2_derive_would_fire),
		.live_flag = 0,
		.min_baseline_samples = SHADOW_ARM_PILOT_MIN_BASELINE_SAMPLES,
		.win_ratio_per_mille = SHADOW_ARM_PILOT_WIN_RATIO_PER_MILLE,
	},
	/*
	 * Pilot arm: FULL_OR combo probe layered on the BITMASK derive
	 * lane.  would_fire bumps on every BITMASK derive whose picked
	 * mask has popcount >= 2 (a single-bit lane cannot converge on
	 * `(flags & A) && (flags & B)` gates that need both bits set);
	 * would_win bumps on the subset where the accumulated OR
	 * differs from the value the live single-bit lane just
	 * emitted, i.e. the combo probe would have contributed a value
	 * the existing lane did not.  No live counterpart yet.
	 */
	[SHADOW_ARM_CMP_HYP_BITMASK_FULL_OR] = {
		.name = "cmp_hyp_bitmask_full_or",
		.would_win_offset =
			offsetof(struct kcov_shared,
				 cmp_hyp_bitmask_full_or_would_win),
		.live_win_offset = 0,
		.baseline_offset =
			offsetof(struct kcov_shared,
				 cmp_hyp_bitmask_full_or_would_fire),
		.live_flag = 0,
		.min_baseline_samples = SHADOW_ARM_PILOT_MIN_BASELINE_SAMPLES,
		.win_ratio_per_mille = SHADOW_ARM_PILOT_WIN_RATIO_PER_MILLE,
	},
	/*
	 * Pilot arm: ANDNOT_TOGGLE combo probe layered on the same
	 * lane.  would_fire bumps on every BITMASK derive where the
	 * complement of the observed-bits set inside the operand
	 * width holds 1..8 bits -- a plausible disallowed-bit mask for
	 * an `x & ~c` allow-mask check; would_win bumps on the subset
	 * where at least one (mask | one-disallowed-bit) candidate
	 * differs from the value the live lane emitted.  No live
	 * counterpart yet.
	 */
	[SHADOW_ARM_CMP_HYP_BITMASK_ANDNOT_TOGGLE] = {
		.name = "cmp_hyp_bitmask_andnot_toggle",
		.would_win_offset =
			offsetof(struct kcov_shared,
				 cmp_hyp_bitmask_andnot_toggle_would_win),
		.live_win_offset = 0,
		.baseline_offset =
			offsetof(struct kcov_shared,
				 cmp_hyp_bitmask_andnot_toggle_would_fire),
		.live_flag = 0,
		.min_baseline_samples = SHADOW_ARM_PILOT_MIN_BASELINE_SAMPLES,
		.win_ratio_per_mille = SHADOW_ARM_PILOT_WIN_RATIO_PER_MILLE,
	},
	/*
	 * Field-scoped CMP inject shadow.  baseline
	 * (cmp_field_consumer_would_pick) bumps on every post-guard
	 * eligible would-pick the field consumer observes -- the pool
	 * was populated, the (desc, field) key resolved, and the
	 * generator-invariant guard classified the target as safe to
	 * inject; would-win (cmp_field_consumer_would_value_differs)
	 * bumps on the subset where the elected pool entry's value
	 * differs from the value the generator was about to write, i.e.
	 * a live-arm flip at that site would swap a different byte on
	 * the wire.  Stricter per-arm criterion than the pilot band --
	 * baseline floor of 100 samples and 100/1000 win threshold --
	 * matching the sibling non-const relational entry: the field
	 * pool's fill rate is currently thin (only the two timespec
	 * fields are wired end-to-end) and a lower floor would surface
	 * on run-to-run noise.  No live counterpart yet --
	 * cmp_field_consumer_live_arm stays off; wiring the flip is a
	 * separate follow-up.
	 *
	 * READINESS gate, NOT a coverage proxy: surfacing a "ready to
	 * promote" line for this arm means "the field-inject candidate
	 * shows a high arg-change rate at eligible sites, worth a
	 * live-flip coverage experiment", NOT "promote now".  The
	 * live-flip decision remains a human call on the follow-up.
	 */
	[SHADOW_ARM_CMP_FIELD_SCOPED_INJECT] = {
		.name = "cmp_field_scoped_inject",
		.would_win_offset =
			offsetof(struct kcov_shared,
				 cmp_field_consumer_would_value_differs),
		.live_win_offset = 0,
		.baseline_offset =
			offsetof(struct kcov_shared,
				 field_consumer.cmp_field_consumer_would_pick),
		.live_flag = 0,
		.min_baseline_samples = 100,
		.win_ratio_per_mille = 100,
	},
	/*
	 * Shared-tier cold-serve shadow.  baseline
	 * (cmp_shared_tier_shadow_warmstart_eligible) bumps once per
	 * cmp_hints_try_get_ex() cold-miss return where the shared tier
	 * had at least one non-entry-path IP available to seed from --
	 * the OPPORTUNITY size a live cold-serve would consume; would-
	 * win (cmp_shared_tier_shadow_would_confirm) bumps on the subset
	 * where the deterministically elected (cmp_ip, value, size)
	 * triple from the shared tier is already present in THIS nr's
	 * own native durable / recent pool at probe time (exact identity
	 * match).  Ratio is the fraction of shared-tier cold-serve
	 * opportunities whose elected value the native evidence for this
	 * syscall already corroborates -- the "shared serve would agree
	 * with what we would eventually learn locally" measurement the
	 * cold-serve go / no-go decision needs.
	 *
	 * Stricter per-arm criterion than the pilot band -- baseline
	 * floor of 100 samples and 250/1000 win threshold -- matching
	 * the sibling shared-tier lane's noisier population profile
	 * (cross-syscall shared entries + entry-path filtering leave a
	 * wider variance envelope than the per-nr equality baselines).
	 * A live counterpart exists (cmp_shared_tier_serves under
	 * COMBINED mode) but is not wired here: this arm onboards the
	 * MEASURE half only; live_flag stays 0 and the promotion
	 * decision is a separate human call once the ratio stabilises.
	 *
	 * READINESS gate, NOT a coverage proxy: surfacing a "ready to
	 * promote" line means "the shared-tier cold-serve elects
	 * triples that agree with local native evidence at a high
	 * enough rate to warrant flipping the live cold-serve on by
	 * default", NOT "promote now".  "Present now" is a conservative
	 * floor per the counter's doc-comment in include/kcov.h.
	 */
	[SHADOW_ARM_CMP_SHARED_TIER_COLDSERVE] = {
		.name = "cmp_shared_tier_coldserve",
		.would_win_offset =
			offsetof(struct kcov_shared,
				 cmp_shared_tier_shadow_would_confirm),
		.live_win_offset = 0,
		.baseline_offset =
			offsetof(struct kcov_shared,
				 cmp_shared_tier_shadow_warmstart_eligible),
		.live_flag = 0,
		.min_baseline_samples = 100,
		.win_ratio_per_mille = 250,
	},
};

/*
 * Resolve an offsetof() locator into a live counter pointer inside
 * the runtime kcov_shm mapping.  Caller must hold kcov_shm non-NULL.
 * Reads and writes to the returned pointer must use __atomic_ ops --
 * the shadow probe writes with __ATOMIC_RELAXED __atomic_fetch_add
 * from every child.
 */
static const unsigned long *shadow_arm_counter(size_t offset)
{
	return (const unsigned long *)((const char *)kcov_shm + offset);
}

void shadow_promotion_evaluate(void)
{
	unsigned int i;

	if (kcov_shm == NULL)
		return;

	for (i = 0; i < SHADOW_ARM_NR; i++) {
		const struct shadow_arm *arm = &shadow_arm_registry[i];
		unsigned long baseline;
		unsigned long would_win;

		/*
		 * Already-promoted arms are excluded from surfacing.
		 * Inert in this pilot (live_flag stays 0), but keeps
		 * the guard in place for the follow-up that lands a
		 * live counterpart -- flipping live_flag will suppress
		 * repeat "ready to promote" chatter without needing a
		 * separate one-shot latch.
		 */
		if (arm->live_flag != 0)
			continue;

		/*
		 * Snapshot the pair in baseline-then-would-win order:
		 * baseline is the divisor, so if a concurrent bump
		 * lands between the two loads the observed ratio can
		 * only get MORE conservative, never less.  If baseline
		 * fails the sample floor there is no point reading
		 * would-win at all.
		 */
		baseline = __atomic_load_n(
			shadow_arm_counter(arm->baseline_offset),
			__ATOMIC_RELAXED);
		if (baseline < arm->min_baseline_samples)
			continue;
		would_win = __atomic_load_n(
			shadow_arm_counter(arm->would_win_offset),
			__ATOMIC_RELAXED);

		/*
		 * Criterion (2): would_win / baseline >= threshold,
		 * checked with the /1000 cross-multiply the surrounding
		 * per_mille block already uses.  would_win is bounded
		 * by baseline in the shadow probe (both are
		 * incremented from the same call site), so
		 * would_win * 1000 fits an unsigned long for any run
		 * length short of 2^54 baseline samples.
		 */
		if (would_win * 1000UL <
		    baseline * arm->win_ratio_per_mille)
			continue;

		/*
		 * Criterion (3) -- "no rejected-struct / invalid-
		 * syscall regression beyond a small bound" -- is
		 * TRIVIALLY MET for a shadow-only arm: nothing on the
		 * generation path is affected, so promotion cannot
		 * have regressed the reject / invalid-syscall stream
		 * yet.  When the arm eventually acquires a live
		 * counterpart (live_win_offset != 0), the criterion
		 * grows a live-vs-baseline regression gate that reads
		 * the rejected-syscall counter for the arm's syscall
		 * class and compares it against the pre-flip baseline.
		 * Documented here so the follow-up knows where to
		 * wire it.
		 */

		output(0,
		       "shadow arm %s: criterion met (would-win %lu vs baseline %lu) -- ready to promote\n",
		       arm->name, would_win, baseline);
	}
}
