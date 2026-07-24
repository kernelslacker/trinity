/*
 * SHADOW typed-hypothesis credit path.
 *
 * Split out of hyp.c: the credit-side resolver (cmp_hyp_find_for_credit),
 * the per-outcome field / flat-counter selectors, and both public credit
 * entry points (cmp_hyp_credit_outcome, cmp_hyp_credit_consume).
 *
 * Consumer contract mirrors the observe side: writers (cmp_hyp_observe)
 * run under the matching durable cmp_hint_pool lock; this file reads
 * lock-free with the RELAXED-load discipline every SHADOW reader uses,
 * and the count > cap bail bounds the walk against torn-read corruption.
 */

#include <stdint.h>

#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "cmp_hints/hyp-internal.h"
#include "kcov.h"
#include "shm.h"

/*
 * Resolve the would-have-been-chosen hypothesis for a (cmp_ip, width,
 * value) tuple against the SHADOW hyp_pool at (nr, do32).  Walks the
 * pool once and returns the most-specific kind whose stored shape
 * explains the value: EXACT (exemplar == value) > ENUM_FAMILY (lo..hi
 * cluster containing value) > BITMASK (single-bit value set in mask)
 * > RANGE (lo..hi interval containing value).  Returns NULL if no
 * hypothesis at the matching (cmp_ip, width) explains the value -- the
 * picked constant pre-dates the inference layer or sits in a slot the
 * observer never fired, both of which are unobservable from the credit
 * side.  Same RELAXED-load discipline as the rest of the SHADOW reader
 * path: torn fields tolerate the consumer-side advisory contract.
 */
/*
 * BOUNDARY credit window: |value - exemplar| <= 2 explains values the
 * N-1 / N+1 / N+/-2 derive ladder produces.  The strict-inequality case
 * the lane is built for needs +/-1; the wider +/-2 slot covers the
 * sweep arm without inflating the window so far that an unrelated
 * value-near-N collision is plausibly attributable.  Matches the same
 * order of magnitude as the derive ladder.
 */
#define CMP_HYP_BOUNDARY_CREDIT_WINDOW 2U

static struct cmp_hypothesis *cmp_hyp_find_for_credit(struct cmp_hyp_pool *pool,
						      unsigned long cmp_ip,
						      uint8_t width,
						      uint64_t value)
{
	struct cmp_hypothesis *enum_match = NULL;
	struct cmp_hypothesis *bitmask_match = NULL;
	struct cmp_hypothesis *range_match = NULL;
	struct cmp_hypothesis *boundary_match = NULL;
	unsigned int i, n = pool->count;
	bool single_bit = (value != 0) && ((value & (value - 1)) == 0);

	if (n > CMP_HYP_PER_SYSCALL)
		return NULL;
	for (i = 0; i < n; i++) {
		struct cmp_hypothesis *h = &pool->entries[i];

		if (h->cmp_ip != (uint64_t)cmp_ip || h->width != width)
			continue;
		switch (h->kind) {
		case CMP_HYP_EXACT:
			if (h->exemplar == value)
				return h;
			break;
		case CMP_HYP_ENUM_FAMILY:
			if (value >= h->lo && value <= h->hi && enum_match == NULL)
				enum_match = h;
			break;
		case CMP_HYP_BITMASK:
			if (single_bit && (h->mask & value) != 0
			    && bitmask_match == NULL)
				bitmask_match = h;
			break;
		case CMP_HYP_RANGE:
			if (value >= h->lo && value <= h->hi && range_match == NULL)
				range_match = h;
			break;
		case CMP_HYP_BOUNDARY:
			if (boundary_match == NULL) {
				uint64_t ex = h->exemplar;
				uint64_t d = (value >= ex)
					? (value - ex)
					: (ex - value);

				if (d <= CMP_HYP_BOUNDARY_CREDIT_WINDOW)
					boundary_match = h;
			}
			break;
		default:
			break;
		}
	}
	if (enum_match != NULL)
		return enum_match;
	if (bitmask_match != NULL)
		return bitmask_match;
	if (range_match != NULL)
		return range_match;
	if (boundary_match != NULL && kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->cmp_hyp_results.cmp_hyp_boundary_credit_window_hits,
				   1UL, __ATOMIC_RELAXED);
	return boundary_match;
}

/*
 * Per-outcome counter selector.  Returns the per-hypothesis u64 field
 * to bump for OUTCOME; a returned NULL means the outcome falls outside
 * the published menu (caller treats as a no-op so a future enumerator
 * addition that forgets a matching arm here surfaces as a quiet skip
 * rather than an out-of-bounds write).
 */
static uint64_t *cmp_hyp_outcome_field(struct cmp_hypothesis *h,
				       enum cmp_hyp_outcome outcome)
{
	switch (outcome) {
	case CMP_HYP_OUTCOME_PC_WIN:		return &h->pc_wins;
	case CMP_HYP_OUTCOME_TRANSITION_WIN:	return &h->transition_wins;
	case CMP_HYP_OUTCOME_CMP_NOVELTY:	return &h->cmp_novelty_wins;
	case CMP_HYP_OUTCOME_CORPUS_SAVE:	return &h->corpus_save_wins;
	case CMP_HYP_OUTCOME_MISS:		return &h->misses;
	case CMP_HYP_OUTCOME_DISABLED:		return &h->disabled_skips;
	case CMP_HYP_OUTCOME_DESTRUCTIVE_SKIP:	return &h->destructive_skips;
	case CMP_HYP_OUTCOME_CONTEXT_SKIP:	return &h->context_skips;
	case CMP_HYP_OUTCOME_NR:
	default:
		return NULL;
	}
}

/*
 * Map an outcome onto the matching kcov_shm flat counter so the
 * fleet-level rollup tracks the per-hypothesis credit.
 */
static unsigned long *cmp_hyp_outcome_flat(enum cmp_hyp_outcome outcome)
{
	if (kcov_shm == NULL)
		return NULL;
	switch (outcome) {
	case CMP_HYP_OUTCOME_PC_WIN:		return &kcov_shm->hyp_flat.cmp_hyp_pc_wins;
	case CMP_HYP_OUTCOME_TRANSITION_WIN:	return &kcov_shm->hyp_flat.cmp_hyp_transition_wins;
	case CMP_HYP_OUTCOME_CMP_NOVELTY:	return &kcov_shm->hyp_flat.cmp_hyp_cmp_novelty_wins;
	case CMP_HYP_OUTCOME_CORPUS_SAVE:	return &kcov_shm->hyp_flat.cmp_hyp_corpus_save;
	case CMP_HYP_OUTCOME_MISS:		return &kcov_shm->hyp_flat.cmp_hyp_misses;
	case CMP_HYP_OUTCOME_DISABLED:		return &kcov_shm->hyp_flat.cmp_hyp_disabled_skips;
	case CMP_HYP_OUTCOME_DESTRUCTIVE_SKIP:	return &kcov_shm->hyp_flat.cmp_hyp_destructive;
	case CMP_HYP_OUTCOME_CONTEXT_SKIP:	return &kcov_shm->hyp_flat.cmp_hyp_context_skip;
	default:
		return NULL;
	}
}

void cmp_hyp_credit_outcome(unsigned int nr, bool do32, unsigned long cmp_ip,
			    unsigned long value, unsigned int size,
			    enum cmp_hyp_outcome outcome)
{
	struct cmp_hyp_pool *pool;
	struct cmp_hypothesis *h;
	uint64_t *field;
	unsigned long *flat;
	uint8_t width;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		return;
	if ((unsigned int)outcome >= CMP_HYP_OUTCOME_NR)
		return;

	width = (uint8_t)size;
	pool = &cmp_hints_shm->hyp_pools[nr][do32 ? 1 : 0];

	/* Lock-free read against the parallel hyp_pool grid.  Writers
	 * (cmp_hyp_observe) run under the matching durable cmp_hint_pool
	 * lock so a torn count or a half-written entry is possible from
	 * this side; the find walk tolerates both -- a misread kind /
	 * exemplar at worst drops the credit, never indexes off the
	 * array thanks to the count > cap bail. */
	h = cmp_hyp_find_for_credit(pool, cmp_ip, width, (uint64_t)value);
	if (h == NULL)
		return;

	field = cmp_hyp_outcome_field(h, outcome);
	if (field == NULL)
		return;
	__atomic_fetch_add(field, 1UL, __ATOMIC_RELAXED);

	flat = cmp_hyp_outcome_flat(outcome);
	if (flat != NULL)
		__atomic_fetch_add(flat, 1UL, __ATOMIC_RELAXED);

	/*
	 * Per-syscall + per-kind outcome partition.  Strictly additive
	 * mirrors of the flat outcome counter just bumped above; the
	 * per-syscall arrays are paired with per_syscall_cmp_injected /
	 * per_syscall_cmp_hint_pc_wins so the cmp-frontier weight can
	 * route on a real conversion rate, and the per-kind arrays let
	 * the periodic dump answer "which kind is actually converting"
	 * without a separate hyp-pool walk.  Only the outcome channels
	 * that exist as per-syscall partitions today bump per-syscall;
	 * per-kind covers every kind-relevant outcome.
	 */
	if (kcov_shm != NULL) {
		unsigned long *per_nr_field = NULL;

		switch (outcome) {
		case CMP_HYP_OUTCOME_TRANSITION_WIN:
			per_nr_field = &kcov_shm->cmp_hint_ps.per_syscall_cmp_hint_transition_wins[nr];
			break;
		case CMP_HYP_OUTCOME_MISS:
			per_nr_field = &kcov_shm->cmp_hint_ps.per_syscall_cmp_hint_misses[nr];
			break;
		case CMP_HYP_OUTCOME_CORPUS_SAVE:
			per_nr_field = &kcov_shm->cmp_hint_ps.per_syscall_cmp_hint_corpus_saves[nr];
			break;
		case CMP_HYP_OUTCOME_DESTRUCTIVE_SKIP:
			per_nr_field = &kcov_shm->cmp_hint_ps.per_syscall_cmp_hint_destructive_skips[nr];
			break;
		case CMP_HYP_OUTCOME_CMP_NOVELTY:
			per_nr_field = &kcov_shm->cmp_hint_ps.per_syscall_cmp_hint_cmp_novelty_wins[nr];
			break;
		default:
			break;
		}
		if (per_nr_field != NULL)
			__atomic_fetch_add(per_nr_field, 1UL, __ATOMIC_RELAXED);

		if (h->kind < CMP_HYP_KIND_NR) {
			unsigned long *per_kind_field = NULL;

			switch (outcome) {
			case CMP_HYP_OUTCOME_PC_WIN:
				per_kind_field = &kcov_shm->cmp_hyp_results.cmp_hyp_pc_wins_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_TRANSITION_WIN:
				per_kind_field = &kcov_shm->cmp_hyp_results.cmp_hyp_transition_wins_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_MISS:
				per_kind_field = &kcov_shm->cmp_hyp_results.cmp_hyp_misses_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_CORPUS_SAVE:
				per_kind_field = &kcov_shm->cmp_hyp_results.cmp_hyp_corpus_save_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_DESTRUCTIVE_SKIP:
				per_kind_field = &kcov_shm->cmp_hyp_results.cmp_hyp_destructive_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_CONTEXT_SKIP:
				per_kind_field = &kcov_shm->cmp_hyp_results.cmp_hyp_context_skip_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_CMP_NOVELTY:
				per_kind_field = &kcov_shm->cmp_hyp_results.cmp_hyp_cmp_novelty_wins_by_kind[h->kind];
				break;
			default:
				break;
			}
			if (per_kind_field != NULL)
				__atomic_fetch_add(per_kind_field, 1UL, __ATOMIC_RELAXED);
		}
	}

	/*
	 * SHADOW scoring pass.  Recompute h->score_bucket from the per-hyp
	 * evidence counters just bumped above, and evaluate the would-
	 * promote / would-demote predicate the live state machine will
	 * eventually own.  Pure observation: h->state is NOT mutated and
	 * remains CMP_HYP_STATE_OBSERVED for every entry.  The bucket
	 * write is u8 and never read by the pick/inject path; the kcov_shm
	 * arrays are SHADOW telemetry.
	 *
	 * Counters are loaded RELAXED -- they race with concurrent
	 * credit_outcome() calls on the same hyp from sibling children.
	 * A torn read at worst computes a slightly stale bucket / mis-
	 * attributes one promote-vs-demote bump; both lanes converge as
	 * subsequent credits land.
	 *
	 *   wins = pc_wins + transition_wins + corpus_save_wins
	 *   pen  = misses + disabled_skips + destructive_skips + context_skips
	 *
	 * cmp_novelty_wins is intentionally excluded from both sides per the
	 * [11-feedback-loop] discipline that keeps CMP-novelty separate from
	 * PC-edge conversion.
	 *
	 * Bucketing (8 bands, fits in u8):
	 *   0  idle  (wins == 0 && pen == 0)
	 *   1  penalty-only (wins == 0, pen >= 1)
	 *   2  heavy net-negative (pen >= wins + 4)
	 *   3  slight net-negative (wins < pen < wins + 4)
	 *   4  break-even (wins == pen, both >= 1)
	 *   5  small net-positive (1 <= wins - pen < 4)
	 *   6  moderate net-positive (4 <= wins - pen < 16)
	 *   7  strong net-positive (wins - pen >= 16)
	 *
	 * Underflow on `wins - pen` is guarded by the pen-side branches
	 * above it -- bands 5..7 only execute when wins > pen.
	 */
	{
		uint64_t pc = __atomic_load_n(&h->pc_wins, __ATOMIC_RELAXED);
		uint64_t tr = __atomic_load_n(&h->transition_wins,
					      __ATOMIC_RELAXED);
		uint64_t cs = __atomic_load_n(&h->corpus_save_wins,
					      __ATOMIC_RELAXED);
		uint64_t ms = __atomic_load_n(&h->misses, __ATOMIC_RELAXED);
		uint64_t ds = __atomic_load_n(&h->disabled_skips,
					      __ATOMIC_RELAXED);
		uint64_t xs = __atomic_load_n(&h->destructive_skips,
					      __ATOMIC_RELAXED);
		uint64_t ks = __atomic_load_n(&h->context_skips,
					      __ATOMIC_RELAXED);
		uint64_t wins = pc + tr + cs;
		uint64_t pen = ms + ds + xs + ks;
		uint8_t bucket;
		bool would_promote = (pc | tr | cs) != 0;
		bool would_demote = !would_promote && ms >= 8;

		if (wins == 0)
			bucket = (pen == 0) ? 0 : 1;
		else if (pen >= wins + 4)
			bucket = 2;
		else if (pen > wins)
			bucket = 3;
		else if (pen == wins)
			bucket = 4;
		else if (wins - pen < 4)
			bucket = 5;
		else if (wins - pen < 16)
			bucket = 6;
		else
			bucket = 7;
		__atomic_store_n(&h->score_bucket, bucket, __ATOMIC_RELAXED);

		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_results.cmp_hyp_score_bucket_census[bucket],
				1UL, __ATOMIC_RELAXED);

		if (kcov_shm != NULL && h->kind < CMP_HYP_KIND_NR) {
			if (would_promote)
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_results.cmp_hyp_would_promote_by_kind[h->kind],
					1UL, __ATOMIC_RELAXED);
			else if (would_demote)
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_results.cmp_hyp_would_demote_by_kind[h->kind],
					1UL, __ATOMIC_RELAXED);
		}

		/*
		 * Live h->state mutation.  The would_promote / would_demote
		 * predicates above were stranded telemetry until now; here
		 * we drive the real state-machine transition off them so
		 * the picker (next commit) can route on h->state.
		 *
		 *   OBSERVED + would_promote  -> PROMOTED  (first win)
		 *   DEMOTED  + would_promote  -> OBSERVED  (revive --
		 *                                earn promotion again)
		 *   OBSERVED + would_demote   -> DEMOTED
		 *   DEMOTED  + sustained miss -> RETIRED   (>= retire
		 *                                threshold misses, still
		 *                                no wins -- dead end)
		 *
		 * RELAXED load/store mirrors the score_bucket store
		 * directly above: concurrent credit_outcome calls on the
		 * same hypothesis from sibling children race; a torn
		 * write at worst mis-attributes a single transition;
		 * the state machine is monotonic in the long run and
		 * subsequent credits converge.  PROMOTED only reverts
		 * via DEMOTED (an explicit miss-stream); DEMOTED ->
		 * RETIRED is terminal.  TESTING is left as a future
		 * intermediate -- a per-pick mutation that does not fit
		 * the credit-side hook.
		 */
		{
			uint8_t old_state = __atomic_load_n(&h->state,
							    __ATOMIC_RELAXED);
			uint8_t new_state = old_state;

			if (would_promote && old_state == CMP_HYP_STATE_OBSERVED)
				new_state = CMP_HYP_STATE_PROMOTED;
			else if (would_promote && old_state == CMP_HYP_STATE_DEMOTED)
				new_state = CMP_HYP_STATE_OBSERVED;
			else if (would_demote && old_state == CMP_HYP_STATE_OBSERVED)
				new_state = CMP_HYP_STATE_DEMOTED;
			else if (old_state == CMP_HYP_STATE_DEMOTED &&
				 ms >= CMP_HYP_RETIRE_MISS_THRESHOLD &&
				 (pc | tr | cs) == 0)
				new_state = CMP_HYP_STATE_RETIRED;

			if (new_state != old_state) {
				__atomic_store_n(&h->state, new_state,
						 __ATOMIC_RELAXED);
				if (kcov_shm != NULL &&
				    old_state < CMP_HYP_STATE_NR &&
				    new_state < CMP_HYP_STATE_NR)
					__atomic_fetch_add(
						&kcov_shm->cmp_hyp_results.cmp_hyp_state_transitions[old_state][new_state],
						1UL, __ATOMIC_RELAXED);
			}
		}
	}
}

/*
 * SHADOW per-hypothesis credit at hint-pull (consume) time.  Resolved
 * via the same EXACT > ENUM_FAMILY > BITMASK > RANGE specificity
 * ladder as cmp_hyp_credit_outcome(); on a hit, bumps the per-
 * hypothesis consumed_count and the flat cmp_hyp_consumed kcov_shm
 * counter so the fleet sees the typed-consumer denominator the
 * follow-up live-pick will weigh outcomes against.
 */
void cmp_hyp_credit_consume(unsigned int nr, bool do32,
			    unsigned long cmp_ip, unsigned long value,
			    unsigned int size)
{
	struct cmp_hyp_pool *pool;
	struct cmp_hypothesis *h;
	uint8_t width;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		return;

	width = (uint8_t)size;
	pool = &cmp_hints_shm->hyp_pools[nr][do32 ? 1 : 0];

	h = cmp_hyp_find_for_credit(pool, cmp_ip, width, (uint64_t)value);
	if (h == NULL)
		return;

	__atomic_fetch_add(&h->consumed_count, 1UL, __ATOMIC_RELAXED);
	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->hyp_flat.cmp_hyp_consumed, 1UL,
				   __ATOMIC_RELAXED);
		__atomic_fetch_add(&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_consumed_by_kind[h->kind],
				   1UL, __ATOMIC_RELAXED);
	}
}
