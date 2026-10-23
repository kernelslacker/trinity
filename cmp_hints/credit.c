/*
 * SHADOW per-entry feedback scoring: the credit drain.  Each parent dispatch
 * ends with one drain of the per-child stash cmp_hints_stash_consumed() fills
 * (PC-mode win or miss, or CMP-mode novelty), which credits the stashed
 * entries and resets it; the typed TRANSITION_WIN and CORPUS_SAVE drains run
 * first and walk the stash without resetting it.
 */

#include <stdint.h>

#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "child.h"
#include "kcov.h"
#include "shm.h"
#include "tables.h"

/*
 * Saturating per-entry counters use a small CAS-saturate loop on the
 * matching pool entry's uint16_t wins/misses field: the common path
 * is one __atomic_compare_exchange_n on the not-yet-saturated counter
 * and short-circuits as soon as the field hits UINT16_MAX so a
 * pathologically hot tuple stops spending atomics once its score has
 * already conclusively dominated the population.  Lock-free scan
 * tolerates a concurrent eviction the same way cmp_hints_try_get_ex does:
 * the picked entry may have been replaced by a sibling between consume
 * and credit, in which case the entries[] re-find at the saved
 * (cmp_ip, value, size) fails, the flat call-level counter still
 * bumps, and the per-entry score for that stash slot is forfeit -- a
 * shadow scoring loss bounded by pool churn.
 */
static void cmp_hint_entry_bump_sat(uint16_t *fld)
{
	uint16_t old;

	old = __atomic_load_n(fld, __ATOMIC_RELAXED);
	while (old < UINT16_MAX) {
		if (__atomic_compare_exchange_n(fld, &old, (uint16_t)(old + 1),
						true,
						__ATOMIC_RELAXED,
						__ATOMIC_RELAXED))
			return;
	}
}

static void cmp_hint_credit_entry_per_syscall(unsigned int nr, bool do32,
					      unsigned long cmp_ip,
					      unsigned long value,
					      unsigned int size,
					      bool win)
{
	struct cmp_hint_pool *pool;
	unsigned int count;
	unsigned int i;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;
	pool = &cmp_hints_shm->pools[nr][do32 ? 1 : 0];
	count = __atomic_load_n(&pool->count, __ATOMIC_ACQUIRE);
	if (count == 0)
		return;
	if (cmp_hints_pool_corrupted(pool, count))
		return;

	for (i = 0; i < count; i++) {
		struct cmp_hint_entry *e = &pool->entries[i];

		if (e->value != value || e->cmp_ip != cmp_ip ||
		    e->size != size)
			continue;
		cmp_hint_entry_bump_sat(win ? &e->wins : &e->misses);
		return;
	}

	if (kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->hint_flat.cmp_hint_credit_entry_evicted,
				   1UL, __ATOMIC_RELAXED);
}

void cmp_hints_feedback_reset_stash(void)
{
	struct childdata *child = this_child();

	if (child == NULL)
		return;
	child->cmp_hints_consumed_count = 0;
}

void cmp_hints_feedback_credit_pc(bool outcome_win)
{
	struct childdata *child = this_child();
	unsigned int i, n;

	if (child == NULL)
		return;
	n = child->cmp_hints_consumed_count;
	if (n == 0)
		return;

	if (kcov_shm != NULL) {
		if (outcome_win)
			__atomic_fetch_add(&kcov_shm->hint_flat.cmp_hint_wins, 1UL,
					   __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->hint_flat.cmp_hint_misses, 1UL,
					   __ATOMIC_RELAXED);
	}

	for (i = 0; i < n; i++) {
		const struct cmp_hint_consumed_entry *e =
			&child->cmp_hints_consumed_stash[i];

		/* Shared-tier serve is QUARANTINED: route the PC outcome
		 * to cmp_hint_tier_shared_wins / _misses ONLY and skip
		 * every native pool credit lane below.  A shared-served
		 * value came from a cross-syscall observation and has
		 * not been locally re-observed, so it must not credit
		 * this nr's native pool per-entry wins/misses (the weight
		 * the live pick would consume), the by-pool / by-tier /
		 * by-age partitions (operator-facing conversion rates),
		 * or the zero-win-budget census.  The
		 * cmp_hint_tier_shared_* pair is the ONLY lane a
		 * served_from_shared stash entry contributes to.  The
		 * `continue` is what enforces the invariant -- every
		 * native lane below this point is unconditionally
		 * skipped. */
		if (e->served_from_shared) {
			if (kcov_shm != NULL)
				__atomic_fetch_add(outcome_win ?
					&kcov_shm->cmp_shared_tier.cmp_hint_tier_shared_wins :
					&kcov_shm->cmp_shared_tier.cmp_hint_tier_shared_misses,
					1UL, __ATOMIC_RELAXED);
			continue;
		}

		switch ((enum cmp_hint_pool_kind)e->pool_kind) {
		case CMP_HINT_POOL_PER_SYSCALL:
			cmp_hint_credit_entry_per_syscall(e->nr, e->do32 != 0,
							  e->cmp_ip, e->value,
							  e->size, outcome_win);
			break;
		case CMP_HINT_POOL_KIND_NR:
		default:
			break;
		}

		/* SHADOW old-flat-pool by-kind PC outcome partition.  Per-
		 * stash-entry bump (the flat cmp_hint_wins / cmp_hint_misses
		 * counters above bump once per parent dispatch), so a dispatch
		 * that stashed several hints lands its PC outcome once per
		 * entry.  Matches the per-tier discipline already used by
		 * cmp_hint_tier_*_wins. */
		if (kcov_shm != NULL &&
		    e->pool_kind < CMP_HINT_POOL_KIND_NR)
			__atomic_fetch_add(outcome_win ?
				&kcov_shm->cmp_hint_pool.cmp_hint_pc_wins_by_pool[e->pool_kind] :
				&kcov_shm->cmp_hint_pool.cmp_hint_misses_by_pool[e->pool_kind],
				1UL, __ATOMIC_RELAXED);

		/* Sibling by-callsite PC outcome partition.  Same per-stash-
		 * entry cadence as the by-pool bump above, keyed on the
		 * callsite the stash was stamped with in
		 * cmp_hints_stash_consumed().  Closes the "callsite split
		 * exists for INJECTED only, win split exists for POOL only"
		 * hole so the raw pool baseline can be projected onto the
		 * typed-eligible callsite buckets (ARG_STRUCT_SIZE and
		 * ARG_RANGE) for a per-callsite conversion rate.  A stash
		 * entry clamped to the CMP_HINT_CALLSITE_NR sentinel is
		 * silently skipped by the bound check. */
		if (kcov_shm != NULL &&
		    e->callsite < CMP_HINT_CALLSITE_NR)
			__atomic_fetch_add(outcome_win ?
				&kcov_shm->hint_callsite.cmp_hint_callsite_pc_wins[e->callsite] :
				&kcov_shm->hint_callsite.cmp_hint_callsite_misses[e->callsite],
				1UL, __ATOMIC_RELAXED);

		/* SHADOW zero-PC-win hard-cool budget census -- see
		 * CMP_HINT_ZERO_WIN_BUDGET_T + struct cmp_hint_pool's
		 * zero_win_streak field for the model.  Only per-syscall pool
		 * stash entries participate; the shared-tier sentinel kind is
		 * skipped.
		 *
		 * PC-WIN: exchange-clear the streak and, if the pre-clear
		 * value was already past the budget, count this credit as
		 * a hint the hypothetical cool would have forfeited (the
		 * lost-win lane of _would_save).
		 * PC-MISS: bump the streak; the exact-T post-value marks
		 * the retirement crossing (_would_retire), post-values past
		 * T count as injections the retirement would have
		 * prevented (the saved-miss lane of _would_save).
		 *
		 * cmp_hints_shm null-check mirrors the helper guard in
		 * cmp_hint_credit_entry_per_syscall above; kcov_shm
		 * null-check keeps this measurement-only branch inert when
		 * observability is disabled.  Live pool selection ignores
		 * zero_win_streak, so this branch is byte-identical for the
		 * injection arm.
		 */
		if (cmp_hints_shm != NULL && kcov_shm != NULL &&
		    e->pool_kind == CMP_HINT_POOL_PER_SYSCALL &&
		    e->nr < MAX_NR_SYSCALL) {
			struct cmp_hint_pool *pool =
				&cmp_hints_shm->pools[e->nr][e->do32 != 0 ? 1U : 0U];

			if (outcome_win) {
				uint32_t before = __atomic_exchange_n(
					&pool->zero_win_streak, 0U,
					__ATOMIC_RELAXED);

				if (before >= CMP_HINT_ZERO_WIN_BUDGET_T)
					__atomic_fetch_add(
						&kcov_shm->cmp_hint_pool.cmp_hint_pool_zero_win_would_save,
						1UL, __ATOMIC_RELAXED);
			} else {
				uint32_t after = __atomic_add_fetch(
					&pool->zero_win_streak, 1U,
					__ATOMIC_RELAXED);

				if (after == CMP_HINT_ZERO_WIN_BUDGET_T)
					__atomic_fetch_add(
						&kcov_shm->cmp_hint_pool.cmp_hint_pool_zero_win_would_retire,
						1UL, __ATOMIC_RELAXED);
				else if (after > CMP_HINT_ZERO_WIN_BUDGET_T)
					__atomic_fetch_add(
						&kcov_shm->cmp_hint_pool.cmp_hint_pool_zero_win_would_save,
						1UL, __ATOMIC_RELAXED);
			}
		}

		/* Typed-hypothesis outcome credit, gated on hyp_injected.
		 *
		 * Before this gate the credit fired on every drained entry,
		 * which meant cmp_hyp_pc_wins counted raw-pool replays whose
		 * value coincidentally matched a stored hypothesis at the
		 * same (cmp_ip, width).  That coincidental credit conflated
		 * "the typed store would have steered toward a converting
		 * value" with "the raw pool happened to serve a value the
		 * typed store also knows about", erasing the signal the
		 * counter exists to surface.
		 *
		 * Under the live arm the gate restricts the credit to stash
		 * entries the inject arm produced.  cmp_hyp_pc_wins now
		 * counts converting calls whose served value was derived
		 * from a typed hypothesis (against the cmp_hyp_live_injected
		 * denominator), so the conversion ratio finally measures
		 * what the typed store earns over the raw replay baseline. */
		if (e->hyp_injected)
			cmp_hyp_credit_outcome(e->nr, e->do32 != 0, e->cmp_ip,
					       e->value, e->size,
					       outcome_win ? CMP_HYP_OUTCOME_PC_WIN
							   : CMP_HYP_OUTCOME_MISS);

		/* Per-tier + per-age conversion partition.  The flat
		 * cmp_hint_wins / cmp_hint_misses counters above bump once
		 * per parent dispatch; the per-stash-entry partition here
		 * is what isolates the freshness signal -- a single
		 * dispatch may have stashed hints from multiple tiers /
		 * age buckets and each lands the outcome on its own
		 * sourcing channel.  Recent-served stash entries roll up
		 * under the recent tier counter and skip the age
		 * histogram (the ring has no per-entry LRU stamp).
		 * Durable-served stash entries roll up under the durable
		 * tier counter and bump the age-bucketed wins/misses
		 * indexed by the bucket stamped on the stash entry at pick
		 * time.  Defensive
		 * clamp on age_bucket mirrors the clamp in
		 * cmp_hints_stash_consumed for the same reason -- a
		 * corrupted stash entry that survived the in-stash clamp
		 * is harmlessly dropped onto the last bucket here. */
		if (kcov_shm == NULL)
			continue;
		if (e->served_from_recent) {
			__atomic_fetch_add(outcome_win ?
					   &kcov_shm->hint_tier.cmp_hint_tier_recent_wins :
					   &kcov_shm->hint_tier.cmp_hint_tier_recent_misses,
					   1UL, __ATOMIC_RELAXED);
		} else {
			uint8_t bucket = e->age_bucket;

			if (bucket >= CMP_HINT_AGE_BUCKETS)
				bucket = (uint8_t)(CMP_HINT_AGE_BUCKETS - 1U);
			__atomic_fetch_add(outcome_win ?
					   &kcov_shm->hint_tier.cmp_hint_tier_durable_wins :
					   &kcov_shm->hint_tier.cmp_hint_tier_durable_misses,
					   1UL, __ATOMIC_RELAXED);
			__atomic_fetch_add(outcome_win ?
					   &kcov_shm->hint_tier.cmp_hint_durable_age_wins[bucket] :
					   &kcov_shm->hint_tier.cmp_hint_durable_age_misses[bucket],
					   1UL, __ATOMIC_RELAXED);
		}
	}

	child->cmp_hints_consumed_count = 0;
}

void cmp_hints_feedback_credit_cmp_novelty(void)
{
	struct childdata *child = this_child();
	unsigned int i, n;

	if (child == NULL)
		return;
	n = child->cmp_hints_consumed_count;
	if (n == 0)
		return;

	if (kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->hint_flat.cmp_hint_cmp_novelty_wins, 1UL,
				   __ATOMIC_RELAXED);

	/* Per spec: CMP-mode novelty is kept SEPARATE from PC-edge win
	 * credit so it cannot masquerade as PC-edge conversion.  Do NOT
	 * bump per-entry wins/misses here -- those are the PC-edge
	 * shadow score the follow-up live-pick will weigh by.  The flat
	 * cmp_hint_cmp_novelty_wins counter is the diagnostic channel
	 * for the CMP-mode signal.
	 *
	 * SHADOW hypothesis layer: credit CMP_NOVELTY against the would-
	 * have-been-chosen hypothesis for every stashed pull.  The typed
	 * cmp_novelty_wins is a peer of pc_wins in struct cmp_hypothesis
	 * for the same reason -- the consumer side must not collapse the
	 * two when ranking hypotheses.
	 */
	for (i = 0; i < n; i++) {
		const struct cmp_hint_consumed_entry *e =
			&child->cmp_hints_consumed_stash[i];

		/* Same hyp_injected gate as the PC drain above: only stash
		 * entries the live inject arm produced credit the typed
		 * hypothesis layer, so cmp_hyp_cmp_novelty_wins measures
		 * typed-arm-driven CMP novelty rather than coincidental
		 * raw-replay overlap with the hypothesis store. */
		if (e->hyp_injected)
			cmp_hyp_credit_outcome(e->nr, e->do32 != 0, e->cmp_ip,
					       e->value, e->size,
					       CMP_HYP_OUTCOME_CMP_NOVELTY);

		/* SHADOW old-flat-pool by-kind CMP-novelty partition.  Kept
		 * SEPARATE from the PC-outcome partition above so harvested-
		 * but-flat novelty cannot masquerade as PC-edge conversion --
		 * mirrors the flat cmp_hint_cmp_novelty_wins vs cmp_hint_wins
		 * split and the typed cmp_hyp_cmp_novelty_wins discipline. */
		if (kcov_shm != NULL &&
		    e->pool_kind < CMP_HINT_POOL_KIND_NR)
			__atomic_fetch_add(
				&kcov_shm->cmp_hint_pool.cmp_hint_cmp_novelty_wins_by_pool[e->pool_kind],
				1UL, __ATOMIC_RELAXED);
	}

	child->cmp_hints_consumed_count = 0;
}

/*
 * Typed-hyp TRANSITION_WIN credit drain.  Walks the stash without
 * resetting it -- the single reset is owned by cmp_hints_feedback_
 * credit_pc() / _cmp_novelty() at end-of-dispatch.  Fires once per
 * hyp_injected stash entry so a parent that stashed two typed-arm
 * hints from different (cmp_ip, width) sites bumps both hypotheses'
 * transition_wins.  Same hyp_injected gate as the PC / CMP-novelty
 * credits: a raw-pool replay that happened to coincide with a stored
 * hypothesis at the served site does NOT bump TRANSITION_WIN.
 */
void cmp_hints_feedback_credit_transition(void)
{
	struct childdata *child = this_child();
	unsigned int i, n;

	if (child == NULL)
		return;
	n = child->cmp_hints_consumed_count;
	if (n == 0)
		return;

	for (i = 0; i < n; i++) {
		const struct cmp_hint_consumed_entry *e =
			&child->cmp_hints_consumed_stash[i];

		if (e->hyp_injected)
			cmp_hyp_credit_outcome(e->nr, e->do32 != 0, e->cmp_ip,
					       e->value, e->size,
					       CMP_HYP_OUTCOME_TRANSITION_WIN);
	}
}

/*
 * Typed-hyp CORPUS_SAVE credit drain.  Same shape as the transition
 * drain above -- walks the stash without resetting it, fires once
 * per hyp_injected entry.  Called from random_syscall/dispatch-step.c when the
 * dispatch produced a novelty signal that minicorpus_save_with_reason
 * accepted, so the credited hypothesis is one whose typed-arm value
 * actually earned its way into the persisted corpus.
 */
void cmp_hints_feedback_credit_corpus_save(void)
{
	struct childdata *child = this_child();
	unsigned int i, n;

	if (child == NULL)
		return;
	n = child->cmp_hints_consumed_count;
	if (n == 0)
		return;

	for (i = 0; i < n; i++) {
		const struct cmp_hint_consumed_entry *e =
			&child->cmp_hints_consumed_stash[i];

		if (e->hyp_injected)
			cmp_hyp_credit_outcome(e->nr, e->do32 != 0, e->cmp_ip,
					       e->value, e->size,
					       CMP_HYP_OUTCOME_CORPUS_SAVE);
	}
}
