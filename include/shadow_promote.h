#pragma once

#include <stddef.h>

/*
 * Shadow-arm promotion evaluator.
 *
 * A "shadow arm" is a candidate derive-class strategy that measures
 * its would-fire (baseline) and would-win counters at runtime without
 * changing generation.  The pilot wires the two BITMASK combination
 * lanes cmp_hyp_bitmask_shadow_probe() populates in kcov_shm today
 * (FULL_OR / ANDNOT_TOGGLE) so their promotion criterion can be
 * evaluated at the stats-tick, uniformly with any future arm.
 *
 * The counters themselves stay declared as scalar fields of
 * struct kcov_shared in include/kcov.h -- the append-only-at-tail
 * layout invariant the shm block promises to consumers is preserved
 * and no incrementer moves.  This registry is a static descriptor
 * table in the parent's .rodata whose entries carry offsets into
 * kcov_shared; the evaluator dereferences them via kcov_shm at
 * eval-time, so both the evaluator and the stats dump read the SAME
 * addresses the shadow probe wrote.  Storing offsets (rather than
 * pointers) lets the table be truly const and side-steps a lazy-
 * initialisation dance keyed on kcov_shm becoming non-NULL.
 *
 * live_flag is inert in this pilot -- shadow_promotion_evaluate()
 * MUST NOT flip it and MUST NOT touch any generation path.  A human
 * decides when to promote an arm; the evaluator only surfaces which
 * arms have accumulated enough evidence to warrant that decision.
 */

struct kcov_shared;

struct shadow_arm {
	const char *name;
	size_t would_win_offset;   /* offsetof(struct kcov_shared, ...) */
	size_t live_win_offset;    /* 0 -> no live counterpart yet */
	size_t baseline_offset;    /* denominator, typically the would-fire */
	int live_flag;             /* 0 in this pilot; a human flips this */
	/*
	 * Promotion criterion, per-arm so a future arm layered on a
	 * noisier or coarser baseline can carry a stricter floor /
	 * threshold without touching the evaluator.
	 */
	unsigned long min_baseline_samples;
	unsigned long win_ratio_per_mille;
};

/*
 * Evaluate every registered arm against its promotion criterion and
 * emit ONE surfacing line for each arm that meets it.  Called from
 * the stats-tick tail of the shadow-measurement render helper; must
 * not be called before kcov_shm is set up (early-out on NULL is
 * defensive).
 */
void shadow_promotion_evaluate(void);
