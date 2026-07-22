/*
 * SHADOW typed-hypothesis store: inference + would-pick + LIVE inject.
 *
 * Layered on top of the raw cmp-hint pools as a PARALLEL table.  The raw
 * pools stay the canonical (cmp_ip, value, size) ledger; this cluster
 * builds typed inferences from those observations and drives the LIVE
 * inject arm that replaces a raw pool value with a hypothesis-derived one
 * on the callsites that opted in.  Every writer runs under the matching
 * durable cmp_hint_pool lock so hyp_pools[nr][do32] is serialised
 * per-(nr, do32) without a second lock of its own.
 */

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "kcov.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "strategy.h"
#include "tables.h"
#include "utils.h"

/*
 * SHADOW typed-hypothesis inference.
 *
 * Called from cmp_hints_flush_pending() once per fresh durable-pool
 * insert, still under that pool's lock -- so writes into
 * hyp_pools[nr][do32 ? 1 : 0] are serialised per-(nr, do32) without a
 * second lock of our own.  Every observation drives one or more typed
 * lanes (EXACT / BITMASK / ENUM_FAMILY / RANGE), subject to the
 * per-kind + per-syscall caps the skeleton reserved.  The resulting
 * hypotheses stay in CMP_HYP_STATE_OBSERVED: no consumer reads them
 * and no injection path substitutes a hypothesis-derived value -- the
 * candidate-API + feedback wiring lands in the follow-up units.
 */
static struct cmp_hypothesis *cmp_hyp_find(struct cmp_hyp_pool *pool,
					   enum cmp_hypothesis_kind kind,
					   unsigned long cmp_ip, uint8_t width)
{
	unsigned int i, n = pool->count;

	if (n > CMP_HYP_PER_SYSCALL)
		return NULL;
	for (i = 0; i < n; i++) {
		struct cmp_hypothesis *h = &pool->entries[i];

		if (h->kind == kind && h->cmp_ip == cmp_ip && h->width == width)
			return h;
	}
	return NULL;
}

static struct cmp_hypothesis *cmp_hyp_find_exact(struct cmp_hyp_pool *pool,
						 unsigned long cmp_ip,
						 uint8_t width, uint64_t value)
{
	unsigned int i, n = pool->count;

	if (n > CMP_HYP_PER_SYSCALL)
		return NULL;
	for (i = 0; i < n; i++) {
		struct cmp_hypothesis *h = &pool->entries[i];

		if (h->kind == CMP_HYP_EXACT && h->cmp_ip == cmp_ip
		    && h->width == width && h->exemplar == value)
			return h;
	}
	return NULL;
}

/*
 * Infer the RANGE-identity discriminators (direction / signedness /
 * relation-class) from an ENUM_FAMILY cluster summary at the same
 * (cmp_ip, width).  KCOV does NOT expose the kernel-side compare
 * operator -- direction is APPROXIMATE.  The heuristic: if the
 * most-recent exemplar sits at the high end of the cluster, treat the
 * probe as ASCENDING (kernel keeps comparing against a rising bound);
 * at the low end, DESCENDING; otherwise UNKNOWN so an un-inferable
 * probe is bucketed honestly rather than force-fit to a guess.
 *
 * Signedness: a bound whose sign bit (relative to its width) is set
 * cannot legitimately share identity with an unsigned probe that
 * happens to have the same numeric value -- a u8 hi=0xFF and an s8
 * hi=-1 are different probes.  Conservative classifier: SIGNED if
 * either bound has the width's sign bit set, else UNSIGNED.
 *
 * Relation: only INSIDE is reachable from the observer side -- KCOV
 * gives us matching operand values, not edge-rejection events.  The
 * OUTSIDE / BOUND / WRAP buckets exist for the future consumer-side
 * probe ladder and stay zero here.
 */
static void cmp_hyp_range_identity_infer(uint64_t lo, uint64_t hi,
					 uint8_t width,
					 const struct cmp_hypothesis *src,
					 uint8_t *out_dir, uint8_t *out_sign,
					 uint8_t *out_rel)
{
	uint64_t sign_bit;

	if (src != NULL && src->seen_count >= 3 && hi > lo) {
		uint64_t ex = src->exemplar;

		if (ex == hi)
			*out_dir = CMP_RANGE_DIR_ASCENDING;
		else if (ex == lo)
			*out_dir = CMP_RANGE_DIR_DESCENDING;
		else
			*out_dir = CMP_RANGE_DIR_UNKNOWN;
	} else {
		*out_dir = CMP_RANGE_DIR_UNKNOWN;
	}

	sign_bit = 1ULL << (width * 8U - 1U);
	if ((lo & sign_bit) != 0 || (hi & sign_bit) != 0)
		*out_sign = CMP_RANGE_SIGN_SIGNED;
	else
		*out_sign = CMP_RANGE_SIGN_UNSIGNED;

	*out_rel = CMP_RANGE_REL_INSIDE;
}

/*
 * RANGE dedup by inferred identity, NOT cmp_ip: two comparison sites
 * that observe the same logical range probe (same bounds, same
 * inferred direction, same width / signedness / relation-class)
 * collapse to ONE entry, and value churn at a single site that does
 * not shift the bounds folds into the same slot.  Bounds are part of
 * identity rather than payload, so a probe whose bounds drift even
 * one step apart is keyed as a distinct hypothesis.
 */
static struct cmp_hypothesis *
cmp_hyp_find_range_by_identity(struct cmp_hyp_pool *pool, uint64_t lo,
			       uint64_t hi, uint8_t width, uint8_t dir,
			       uint8_t sign, uint8_t rel)
{
	unsigned int i, n = pool->count;

	if (n > CMP_HYP_PER_SYSCALL)
		return NULL;
	for (i = 0; i < n; i++) {
		struct cmp_hypothesis *h = &pool->entries[i];

		if (h->kind != CMP_HYP_RANGE || h->width != width)
			continue;
		if (h->lo != lo || h->hi != hi)
			continue;
		if (h->range_direction != dir
		    || h->range_signedness != sign
		    || h->range_relation != rel)
			continue;
		return h;
	}
	return NULL;
}

/*
 * Allocate a fresh hypothesis slot honouring the per-kind sub-cap and
 * the per-syscall total cap.  Returns NULL when either is exhausted
 * and bumps the matching kcov_shm saturation counter so the rejection
 * is visible.  The slot is memset and pre-stamped with identity
 * fields the caller does not have to re-write.
 */
static struct cmp_hypothesis *cmp_hyp_alloc(struct cmp_hyp_pool *pool,
					    enum cmp_hypothesis_kind kind,
					    unsigned int nr, bool do32,
					    unsigned long cmp_ip, uint8_t width)
{
	struct cmp_hypothesis *h;

	if (pool->count >= CMP_HYP_PER_SYSCALL) {
		if (kcov_shm != NULL) {
			__atomic_fetch_add(&kcov_shm->hyp_flat.cmp_hyp_pool_full, 1UL,
					   __ATOMIC_RELAXED);
			__atomic_fetch_add(&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_pool_full_by_kind[kind],
					   1UL, __ATOMIC_RELAXED);
		}
		return NULL;
	}
	if (pool->per_kind_count[kind] >= CMP_HYP_PER_KIND) {
		if (kcov_shm != NULL) {
			__atomic_fetch_add(&kcov_shm->hyp_flat.cmp_hyp_kind_full, 1UL,
					   __ATOMIC_RELAXED);
			__atomic_fetch_add(&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_kind_full_by_kind[kind],
					   1UL, __ATOMIC_RELAXED);
		}
		return NULL;
	}

	h = &pool->entries[pool->count];
	memset(h, 0, sizeof(*h));
	h->nr = nr;
	h->do32 = do32;
	h->width = width;
	h->kind = (uint8_t)kind;
	h->state = CMP_HYP_STATE_OBSERVED;
	h->cmp_ip = (uint64_t)cmp_ip;
	pool->per_kind_count[kind]++;
	pool->count++;
	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->hyp_flat.cmp_hyp_inserted, 1UL,
				   __ATOMIC_RELAXED);
		__atomic_fetch_add(&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_inserted_by_kind[kind],
				   1UL, __ATOMIC_RELAXED);
	}
	return h;
}

void cmp_hyp_observe(unsigned int nr, bool do32, unsigned long cmp_ip,
		     unsigned long value, unsigned int size)
{
	struct cmp_hyp_pool *pool;
	struct cmp_hypothesis *h, *e;
	uint64_t val = (uint64_t)value;
	uint64_t generation = 0;
	uint8_t width;
	bool single_bit;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		return;

	width = (uint8_t)size;
	pool = &cmp_hints_shm->hyp_pools[nr][do32 ? 1 : 0];

	if (kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->hyp_flat.cmp_hyp_observations, 1UL,
				   __ATOMIC_RELAXED);

	/* Wild-write defence: a stomp past the per-syscall cap would let
	 * the find/alloc scans walk off entries[].  Bail and surface it on
	 * the sibling cmp_hyp_pool_overflow counter -- distinct from the
	 * cmp_hyp_pool_full saturation lane so a corruption channel cannot
	 * hide inside legitimate back-pressure. */
	if (pool->count > CMP_HYP_PER_SYSCALL) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_hyp_pool_overflow, 1UL,
					   __ATOMIC_RELAXED);
		return;
	}

	/* The durable pool's generation, advanced in lock-step with the
	 * insert that triggered this observation, is a stable monotonic
	 * clock to stamp last_used_generation against.  Same lock window,
	 * so a plain read is consistent. */
	generation = cmp_hints_shm->pools[nr][do32 ? 1 : 0].generation;

	/*
	 * EXACT lane: per-value identity.  A repeat observation refreshes
	 * seen_count + last_used_generation; a fresh value tries to take a
	 * slot (subject to the per-kind cap of 2).
	 */
	h = cmp_hyp_find_exact(pool, cmp_ip, width, val);
	if (h != NULL) {
		h->seen_count++;
		h->last_used_generation = generation;
	} else {
		h = cmp_hyp_alloc(pool, CMP_HYP_EXACT, nr, do32, cmp_ip, width);
		if (h != NULL) {
			h->exemplar = val;
			h->lo = val;
			h->hi = val;
			h->seen_count = 1;
			h->last_used_generation = generation;
		}
	}

	/* BITMASK lane: only single-bit observations contribute.  A zero
	 * carries no bit; a multi-bit value would conflate single-bit
	 * evidence with combined-flag exemplars -- those belong to ENUM_FAMILY
	 * below so the consumer side can keep the two scoring families
	 * separate (one-unknown-bit probes vs combination probes). */
	single_bit = (val != 0) && ((val & (val - 1)) == 0);
	if (single_bit) {
		h = cmp_hyp_find(pool, CMP_HYP_BITMASK, cmp_ip, width);
		if (h != NULL) {
			h->mask |= val;
			h->seen_count++;
			if (val < h->lo)
				h->lo = val;
			if (val > h->hi)
				h->hi = val;
			h->exemplar = val;
			h->last_used_generation = generation;
		} else {
			h = cmp_hyp_alloc(pool, CMP_HYP_BITMASK, nr, do32,
					  cmp_ip, width);
			if (h != NULL) {
				h->mask = val;
				h->lo = val;
				h->hi = val;
				h->exemplar = val;
				h->seen_count = 1;
				h->last_used_generation = generation;
			}
		}
	}

	/*
	 * ENUM_FAMILY lane: every observation at (cmp_ip, width) folds into
	 * the per-key cluster summary (lo/hi/mask/seen_count, exemplar =
	 * most-recent).  Distinct from EXACT (per-value dedup) and from
	 * BITMASK (single-bit-only), and deliberately NOT collapsed into
	 * RANGE -- {1, 2, 3} may be three independent modes, not an interval,
	 * so promotion is left to the feedback unit's outcome scoring.
	 */
	e = cmp_hyp_find(pool, CMP_HYP_ENUM_FAMILY, cmp_ip, width);
	if (e != NULL) {
		e->seen_count++;
		e->mask |= val;
		if (val < e->lo)
			e->lo = val;
		if (val > e->hi)
			e->hi = val;
		e->exemplar = val;
		e->last_used_generation = generation;
	} else {
		e = cmp_hyp_alloc(pool, CMP_HYP_ENUM_FAMILY, nr, do32,
				  cmp_ip, width);
		if (e != NULL) {
			e->lo = val;
			e->hi = val;
			e->mask = val;
			e->exemplar = val;
			e->seen_count = 1;
			e->last_used_generation = generation;
		}
	}

	/*
	 * RANGE lane: synthesised only once the ENUM_FAMILY summary at the
	 * same key has accumulated enough observations to suggest a dense
	 * small interval (>= 3 hits, span 2..32).  The entry stays in
	 * CMP_HYP_STATE_OBSERVED -- the spec's promotion trap requires an
	 * interior non-constant pass OR an outside-reject + multiple
	 * inside-passes, which only the outcome-credited feedback unit can
	 * supply.  The probe ladder (lo-1, lo, lo+1, midpoint, hi-1, hi,
	 * hi+1, plus exponential probing when the high side is unknown) is
	 * implicit in {lo, hi}; the consumer derives it at pick time so the
	 * shadow store does not need to materialise it.
	 *
	 * Dedup key is an inferred RANGE-IDENTITY tuple {lo, hi, direction,
	 * width, signedness, relation-class}, NOT cmp_ip.  Two comparison
	 * sites that produce the same logical range probe -- regardless of
	 * the literal constants the kernel happened to compare against --
	 * collapse to ONE entry.  Width and signedness are part of the
	 * identity (per the discriminated-arg discipline): a u32 range and
	 * a u64 range with the same numeric bounds are not the same probe.
	 * Direction is APPROXIMATE -- KCOV cannot recover the operator --
	 * and CMP_RANGE_DIR_UNKNOWN owns un-inferable probes so they are
	 * keyed honestly instead of force-fit to a guess.
	 *
	 * Bound math safety: the > 32 / <= early-bail above guarantees
	 * hi > lo at the subtraction site; the second-line check below
	 * defends against a torn read of an in-flight ENUM entry under
	 * the RELAXED reader discipline the rest of the shadow path uses.
	 */
	if (e == NULL || e->seen_count < 3 || e->hi <= e->lo
	    || (e->hi - e->lo) > 32) {
		goto boundary;
	}
	{
		uint64_t r_lo = e->lo, r_hi = e->hi;
		uint8_t dir, sign, rel;

		if (r_hi < r_lo)
			goto boundary;

		cmp_hyp_range_identity_infer(r_lo, r_hi, width, e,
					     &dir, &sign, &rel);
		h = cmp_hyp_find_range_by_identity(pool, r_lo, r_hi, width,
						   dir, sign, rel);
		if (h == NULL) {
			h = cmp_hyp_alloc(pool, CMP_HYP_RANGE, nr, do32,
					  cmp_ip, width);
			if (h != NULL) {
				h->range_direction = dir;
				h->range_signedness = sign;
				h->range_relation = rel;
				h->lo = r_lo;
				h->hi = r_hi;
			}
		}
		if (h != NULL) {
			h->exemplar = e->exemplar;
			h->seen_count = e->seen_count;
			h->last_used_generation = generation;
		}
	}

boundary:
	/*
	 * BOUNDARY lane: per-(cmp_ip, width) summary populated from a
	 * SINGLE const observation -- explicitly NOT gated on RANGE's
	 * seen_count >= 3 / span 2..32 rule, which is what starves the
	 * single-boundary inequality case (one inequality `x < N` at one
	 * site sees the same const N every fire -> span 0 -> RANGE never
	 * synthesises, even though N+/-1 is the value that passes).
	 * Shape mirrors ENUM_FAMILY's bookkeeping (exemplar = most-recent
	 * const, lo/hi = running min/max over consts seen at this key)
	 * but the BOUNDARY derive arm emits a neighbourhood ladder rather
	 * than interior members, hitting the strict-inequality boundary
	 * EXACT and RANGE both refuse to produce.
	 */
	{
		bool fresh_boundary = false;

		h = cmp_hyp_find(pool, CMP_HYP_BOUNDARY, cmp_ip, width);
		if (h == NULL) {
			h = cmp_hyp_alloc(pool, CMP_HYP_BOUNDARY, nr, do32,
					  cmp_ip, width);
			fresh_boundary = (h != NULL);
		}
		if (h != NULL) {
			if (fresh_boundary) {
				h->lo = val;
				h->hi = val;
				h->seen_count = 1;
			} else {
				if (val < h->lo)
					h->lo = val;
				if (val > h->hi)
					h->hi = val;
				h->seen_count++;
			}
			h->exemplar = val;
			h->last_used_generation = generation;
			if (fresh_boundary && kcov_shm != NULL)
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_boundary_inserted,
					1UL, __ATOMIC_RELAXED);
		}
	}
}

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
		__atomic_fetch_add(&kcov_shm->cmp_hyp_boundary_credit_window_hits,
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
				per_kind_field = &kcov_shm->cmp_hyp_pc_wins_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_TRANSITION_WIN:
				per_kind_field = &kcov_shm->cmp_hyp_transition_wins_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_MISS:
				per_kind_field = &kcov_shm->cmp_hyp_misses_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_CORPUS_SAVE:
				per_kind_field = &kcov_shm->cmp_hyp_corpus_save_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_DESTRUCTIVE_SKIP:
				per_kind_field = &kcov_shm->cmp_hyp_destructive_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_CONTEXT_SKIP:
				per_kind_field = &kcov_shm->cmp_hyp_context_skip_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_CMP_NOVELTY:
				per_kind_field = &kcov_shm->cmp_hyp_cmp_novelty_wins_by_kind[h->kind];
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
				&kcov_shm->cmp_hyp_score_bucket_census[bucket],
				1UL, __ATOMIC_RELAXED);

		if (kcov_shm != NULL && h->kind < CMP_HYP_KIND_NR) {
			if (would_promote)
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_would_promote_by_kind[h->kind],
					1UL, __ATOMIC_RELAXED);
			else if (would_demote)
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_would_demote_by_kind[h->kind],
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
						&kcov_shm->cmp_hyp_state_transitions[old_state][new_state],
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

/*
 * Picker reroll denominator for DEMOTED slots.  A DEMOTED slot is
 * normally invisible to the picker, but gets a 1-in-N chance to be
 * surfaced when no PROMOTED / OBSERVED slot exists for the same
 * (cmp_ip, width) at the given kind.  Keeps a path to revival open:
 * a re-rolled DEMOTED that earns a win flips back to OBSERVED via
 * cmp_hyp_credit_outcome's DEMOTED + would_promote transition. */
#define CMP_HYP_DEMOTED_RETRY_DENOM	64U

/*
 * Picker.  Walks the typed-hypothesis pool for (cmp_ip, width) -- no
 * value constraint, unlike cmp_hyp_find_for_credit which matches on
 * (cmp_ip, width, value).  Records per-ladder-kind presence as it
 * walks, then applies the SAME specificity ordering
 * cmp_hyp_find_for_credit uses (EXACT > ENUM_FAMILY > BITMASK >
 * RANGE) to choose the pick.  Within each kind, state-aware
 * preference is applied:
 *
 *   PROMOTED  -- first match wins, preferred over OBSERVED
 *   OBSERVED  -- fallback when no PROMOTED slot exists
 *   TESTING   -- treated as OBSERVED (per-pick waystation, no
 *                special handling on the credit-side hook)
 *   DEMOTED   -- surfaced only via the CMP_HYP_DEMOTED_RETRY_DENOM
 *                re-roll, and only when no PROMOTED / OBSERVED slot
 *                exists for this kind -- keeps revival reachable
 *                without polluting the steady-state pick stream
 *   RETIRED   -- never picked
 *
 * Returns the chosen hypothesis or NULL, and writes the per-kind
 * presence mask through *present_out.  Presence reflects what the
 * picker would actually CONSIDER -- RETIRED slots do not register
 * presence, so the per-kind miss attribution downstream is consistent
 * with the picker's view.  (Treating RETIRED as "present" would mark
 * a kind as covered while the picker walks past it, biasing the
 * would_miss telemetry.)
 *
 * Lock-free read against a parallel writer (cmp_hyp_observe under the
 * matching durable cmp_hint_pool lock): a torn count or half-written
 * entry tolerates the same way cmp_hyp_find_for_credit tolerates it --
 * the count > cap bail bounds the walk and a misread kind / cmp_ip at
 * worst drops the shadow attribution for one pull, never indexes off
 * the array.  h->state is read RELAXED -- the credit-side writer is
 * RELAXED too; a torn read at worst routes one pick under a stale
 * state, and the picker is non-mutating so the race is benign.
 */
static struct cmp_hypothesis *
cmp_hyp_would_pick_locked(struct cmp_hyp_pool *pool, unsigned long cmp_ip,
			  uint8_t width,
			  bool present_out[CMP_HYP_KIND_NR])
{
	struct cmp_hypothesis *exact_promoted = NULL, *exact_observed = NULL, *exact_demoted = NULL;
	struct cmp_hypothesis *enum_promoted = NULL, *enum_observed = NULL, *enum_demoted = NULL;
	struct cmp_hypothesis *bitmask_promoted = NULL, *bitmask_observed = NULL, *bitmask_demoted = NULL;
	struct cmp_hypothesis *range_promoted = NULL, *range_observed = NULL, *range_demoted = NULL;
	struct cmp_hypothesis *boundary_promoted = NULL, *boundary_observed = NULL, *boundary_demoted = NULL;
	unsigned int i, n = pool->count;
	unsigned int k;

	for (k = 0; k < CMP_HYP_KIND_NR; k++)
		present_out[k] = false;

	if (n > CMP_HYP_PER_SYSCALL)
		return NULL;
	for (i = 0; i < n; i++) {
		struct cmp_hypothesis *h = &pool->entries[i];
		uint8_t state;
		struct cmp_hypothesis **promoted_slot = NULL;
		struct cmp_hypothesis **observed_slot = NULL;
		struct cmp_hypothesis **demoted_slot = NULL;
		unsigned int present_idx;

		if (h->cmp_ip != (uint64_t)cmp_ip || h->width != width)
			continue;
		switch (h->kind) {
		case CMP_HYP_EXACT:
			promoted_slot = &exact_promoted;
			observed_slot = &exact_observed;
			demoted_slot = &exact_demoted;
			present_idx = CMP_HYP_EXACT;
			break;
		case CMP_HYP_ENUM_FAMILY:
			promoted_slot = &enum_promoted;
			observed_slot = &enum_observed;
			demoted_slot = &enum_demoted;
			present_idx = CMP_HYP_ENUM_FAMILY;
			break;
		case CMP_HYP_BITMASK:
			promoted_slot = &bitmask_promoted;
			observed_slot = &bitmask_observed;
			demoted_slot = &bitmask_demoted;
			present_idx = CMP_HYP_BITMASK;
			break;
		case CMP_HYP_RANGE:
			promoted_slot = &range_promoted;
			observed_slot = &range_observed;
			demoted_slot = &range_demoted;
			present_idx = CMP_HYP_RANGE;
			break;
		case CMP_HYP_BOUNDARY:
			promoted_slot = &boundary_promoted;
			observed_slot = &boundary_observed;
			demoted_slot = &boundary_demoted;
			present_idx = CMP_HYP_BOUNDARY;
			break;
		default:
			continue;
		}

		state = __atomic_load_n(&h->state, __ATOMIC_RELAXED);
		switch (state) {
		case CMP_HYP_STATE_PROMOTED:
			if (*promoted_slot == NULL)
				*promoted_slot = h;
			present_out[present_idx] = true;
			break;
		case CMP_HYP_STATE_OBSERVED:
		case CMP_HYP_STATE_TESTING:
			if (*observed_slot == NULL)
				*observed_slot = h;
			present_out[present_idx] = true;
			break;
		case CMP_HYP_STATE_DEMOTED:
			if (*demoted_slot == NULL)
				*demoted_slot = h;
			present_out[present_idx] = true;
			break;
		case CMP_HYP_STATE_RETIRED:
			if (kcov_shm != NULL)
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_skipped_retired_by_kind[h->kind],
					1UL, __ATOMIC_RELAXED);
			break;
		default:
			break;
		}
	}

#define CMP_HYP_PICK_TIER(p, o, d) do {					\
		if ((p) != NULL) {					\
			if (kcov_shm != NULL)				\
				__atomic_fetch_add(			\
					&kcov_shm->cmp_hyp_picked_by_state[CMP_HYP_STATE_PROMOTED], \
					1UL, __ATOMIC_RELAXED);		\
			return (p);					\
		}							\
		if ((o) != NULL) {					\
			if (kcov_shm != NULL)				\
				__atomic_fetch_add(			\
					&kcov_shm->cmp_hyp_picked_by_state[CMP_HYP_STATE_OBSERVED], \
					1UL, __ATOMIC_RELAXED);		\
			return (o);					\
		}							\
		if ((d) != NULL && ONE_IN(CMP_HYP_DEMOTED_RETRY_DENOM)) { \
			if (kcov_shm != NULL) {				\
				__atomic_fetch_add(			\
					&kcov_shm->cmp_hyp_picked_by_state[CMP_HYP_STATE_DEMOTED], \
					1UL, __ATOMIC_RELAXED);		\
				__atomic_fetch_add(			\
					&kcov_shm->cmp_hyp_demoted_reroll_picked_by_kind[(d)->kind], \
					1UL, __ATOMIC_RELAXED);		\
			}						\
			return (d);					\
		}							\
	} while (0)

	CMP_HYP_PICK_TIER(exact_promoted, exact_observed, exact_demoted);
	CMP_HYP_PICK_TIER(enum_promoted, enum_observed, enum_demoted);
	CMP_HYP_PICK_TIER(bitmask_promoted, bitmask_observed, bitmask_demoted);
	CMP_HYP_PICK_TIER(range_promoted, range_observed, range_demoted);
	CMP_HYP_PICK_TIER(boundary_promoted, boundary_observed, boundary_demoted);

#undef CMP_HYP_PICK_TIER
	return NULL;
}

/*
 * SHADOW would-pick wrapper invoked by cmp_hints_try_get_ex() on every
 * successful raw-pool pick.  Pure observation: bumps the would-pick /
 * would-miss / would-value-differs counters in kcov_shm and returns.
 * The live pick (the *out value cmp_hints_try_get_ex already wrote and
 * the bool true it is about to return) is byte-for-byte unchanged.
 */
void cmp_hyp_would_pick(unsigned int nr, bool do32,
			unsigned long cmp_ip, unsigned int size,
			unsigned long live_value)
{
	struct cmp_hyp_pool *pool;
	struct cmp_hypothesis *picked;
	bool present[CMP_HYP_KIND_NR];
	uint8_t width;
	unsigned int k;
	static const uint8_t ladder_kinds[] = {
		CMP_HYP_EXACT, CMP_HYP_ENUM_FAMILY,
		CMP_HYP_BITMASK, CMP_HYP_RANGE,
		CMP_HYP_BOUNDARY,
	};

	if (kcov_shm == NULL || cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		return;

	width = (uint8_t)size;
	pool = &cmp_hints_shm->hyp_pools[nr][do32 ? 1 : 0];

	picked = cmp_hyp_would_pick_locked(pool, cmp_ip, width, present);
	if (picked != NULL) {
		__atomic_fetch_add(
			&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_would_pick_by_kind[picked->kind],
			1UL, __ATOMIC_RELAXED);
		if (picked->exemplar != (uint64_t)live_value) {
			__atomic_fetch_add(&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_would_value_differs,
					   1UL, __ATOMIC_RELAXED);
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_would_value_differs_by_kind[picked->kind],
				1UL, __ATOMIC_RELAXED);
		}
	}
	for (k = 0; k < ARRAY_SIZE(ladder_kinds); k++) {
		uint8_t lk = ladder_kinds[k];

		if (!present[lk])
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_would_miss_by_kind[lk],
				1UL, __ATOMIC_RELAXED);
	}
	/*
	 * Decoupled BOUNDARY availability census.  Bumped whenever a
	 * BOUNDARY entry is populated at the served (cmp_ip, width) AND
	 * the derive arm would not bail (the guards inside the BOUNDARY
	 * case of cmp_hyp_derive_value always succeed for a non-corrupted
	 * entry, so presence is the binding condition).  Independent of
	 * the EXACT > ENUM > BITMASK > RANGE > BOUNDARY precedence above:
	 * EXACT is populated at every observation and outranks BOUNDARY,
	 * so cmp_hyp_would_pick_by_kind[BOUNDARY] stays structurally near
	 * zero -- the counter below is the lane's headline shadow metric
	 * (how often BOUNDARY would have a neighbour to inject if the
	 * precedence let it through).
	 */
	if (present[CMP_HYP_BOUNDARY])
		__atomic_fetch_add(&kcov_shm->cmp_hyp_boundary_candidate_available,
				   1UL, __ATOMIC_RELAXED);
}

/*
 * Inject rate for the LIVE typed-hypothesis arm under the
 * CMP_RISING_PC_FLAT plateau (channel A below).  Raised from the prior
 * conservative 1/32 to 1/4 (8x) for the conversion-measurement window:
 * at 1/32 a 2h run banks only ~10k typed firings, far short of the
 * ~75k needed to see even one PC win at the raw arm's ~1e-5 rate, so
 * the typed-vs-raw verdict could never resolve in a practical run.
 * 1/4 accumulates enough typed firings to measure the arm; it is
 * deliberately less conservative than the raw baseline (1/16) for that
 * measurement -- revisit (back toward 1/16-1/32) once the rate is known.
 */
#define CMP_HYP_LIVE_INJECT_DENOM	4U

/*
 * Bootstrap channel dice (channel B) for the LIVE typed-hypothesis arm.
 * Fires REGARDLESS of plateau so the inject pipeline can earn its first
 * PC wins on OBSERVED-state hypotheses before the plateau gate has ever
 * opened.  Sparse (~0.4 %) so it cannot drown the raw cmp-hint signal
 * even in the worst case; integrated over a multi-hour run this still
 * accumulates thousands of typed-arm firings, plenty to seed the
 * promotion ladder.  Resolves the circular dependency where
 * cmp_hyp_try_live_inject was gated on a plateau that only opens once
 * PROMOTED hypotheses exist, but PROMOTED hypotheses only appear after
 * cmp_hyp_try_live_inject has fired and earned wins.
 */
#define CMP_HYP_LIVE_INJECT_BOOTSTRAP_DENOM	256U

/*
 * PROMOTED-bypass channel dice (channel C) for the LIVE typed-hypothesis
 * arm.  Cheaper than the bootstrap dice (~1.6 %) because the state
 * machine (cmp_hyp_credit_outcome's DEMOTE / RETIRE on losses, PROMOTE
 * on wins) has already done the throttling work that the plateau gate
 * was approximating: a PROMOTED entry has demonstrably produced a
 * coverage win, so re-firing it cheaply is the warranted bias.  Only
 * applies when cmp_hyp_would_pick_locked returns a PROMOTED entry at
 * the served (cmp_ip, width) -- if the picker returns OBSERVED or NULL,
 * channel C is treated as if its dice had not been rolled (account via
 * NO_MATCH downstream when picker == NULL, otherwise bail).
 */
#define CMP_HYP_LIVE_INJECT_PROMOTED_DENOM	64U

/*
 * Bit-pattern test for the SHADOW pow2 / alignment derive class: true
 * when C is at or within +/-1 of a power of two.  A strict popcount==1
 * test would miss the common off-by-one boundary constants
 * (511 vs 512, 4095 vs 4096) that the pow2 lane's would-emit ladder
 * targets, so the neighbourhood is folded into the eligibility gate
 * itself.  C == 0 is treated as ineligible (round-to-N variants would
 * all collapse to zero and the >>1 / <<1 arms carry no information),
 * matching the empty-mask fallback shape the BITMASK derive uses.
 */
static bool cmp_hyp_is_near_pow2(uint64_t c)
{
	if (c == 0)
		return false;
	if ((c & (c - 1)) == 0)
		return true;
	if (((c + 1) & c) == 0)
		return true;
	if (c >= 1 && ((c - 1) & (c - 2)) == 0 && (c - 1) != 0)
		return true;
	return false;
}

/*
 * SHADOW pow2 / alignment derive-class measurement.  Runs on every
 * derive whose callsite is a size / offset-class argtype
 * (ARG_RANGE / ARG_STRUCT_SIZE) AND whose picked exemplar is at or
 * near a power of two.  Bumps cmp_hyp_pow2_derive_would_fire on
 * eligibility, and cmp_hyp_pow2_derive_would_win when at least one
 * candidate from the {C>>1, C, C<<1, round-to-512, round-to-4096,
 * round-to-page-size} ladder differs from live_out (the value the
 * live derive lane just wrote to *out).  Does NOT touch *out and does
 * NOT emit into the live candidate stream -- pure observation.
 *
 * Argtype gate rationale: flag / enum callsites overlap the existing
 * EXACT / ENUM_FAMILY lanes, so a pow2 lane firing there is wasted
 * pick budget with no coverage headroom.  Size / offset callsites
 * (length caps, struct-size fields, offset arguments) are where
 * powers of two carry real meaning (page-boundary, cache-line,
 * allocator bucket) and where the existing lanes' exemplar / lo /
 * hi / mask candidates do NOT construct the neighbourhood the class
 * targets.
 *
 * Bug-pattern guards: page_size is read via a plain load and clamped
 * to a well-defined power of two before the round-up computation
 * (a torn read of a zero page_size would divide-by-zero the naive
 * form).  The shift arms mask to 64 bits so an out-of-range shift
 * (C == 0 already gated above, C == 2^63 for <<1) does not surface
 * as UB.  The round-up computations use the standard
 * (v + align - 1) & ~(align - 1) form after verifying v + align does
 * not overflow; on overflow the arm is skipped rather than emitting
 * a wrapped value.
 */
static void cmp_hyp_pow2_shadow_probe(const struct cmp_hypothesis *picked,
				      enum cmp_hint_callsite callsite,
				      unsigned long live_out)
{
	uint64_t c, cand;
	uint64_t page_align;
	uint64_t live_val;
	bool differs;

	if (kcov_shm == NULL || picked == NULL)
		return;
	if (callsite != CMP_HINT_CALLSITE_ARG_RANGE &&
	    callsite != CMP_HINT_CALLSITE_ARG_STRUCT_SIZE)
		return;

	c = picked->exemplar;
	if (!cmp_hyp_is_near_pow2(c))
		return;

	__atomic_fetch_add(&kcov_shm->cmp_hyp_pow2_derive_would_fire, 1UL,
			   __ATOMIC_RELAXED);

	live_val = (uint64_t)live_out;
	differs = false;

	/* C>>1 arm: informationless when C == 0 (gated above) or C == 1
	 * (right-shift yields 0, indistinguishable from the empty-mask
	 * fallback). */
	if (c >= 2) {
		cand = c >> 1;
		if (cand != live_val)
			differs = true;
	}

	/* C arm: the exemplar itself.  Existing lanes may already emit it
	 * (EXACT exemplar, ENUM_FAMILY exemplar), which is precisely why
	 * this candidate is expected to MATCH live_val on the equality-
	 * dominated path -- the would_win partition surfaces the rest. */
	if (c != live_val)
		differs = true;

	/* C<<1 arm: gated against high-bit wrap.  c & (1ULL<<63) != 0
	 * would shift the sign bit out; skip cleanly (the round-to-N
	 * arms below still contribute a candidate). */
	if ((c & (1ULL << 63)) == 0) {
		cand = c << 1;
		if (cand != live_val)
			differs = true;
	}

	/* Round-to-512 / 4096: standard (v + align - 1) & ~(align - 1),
	 * skipped when the add would wrap (v > UINT64_MAX - (align - 1)).
	 * The round-DOWN arm collapses to c & ~(align - 1) and is always
	 * well-defined for non-zero c, but a v < align input rounds down
	 * to zero, so the more useful signal is round-UP. */
	if (c <= (uint64_t)~0ULL - 511UL) {
		cand = (c + 511UL) & ~(uint64_t)511UL;
		if (cand != live_val)
			differs = true;
	}
	if (c <= (uint64_t)~0ULL - 4095UL) {
		cand = (c + 4095UL) & ~(uint64_t)4095UL;
		if (cand != live_val)
			differs = true;
	}

	/* Round-to-page-size: page_size is a runtime global, clamp to a
	 * safe power of two (4096) if a torn / zero read would break the
	 * mask math.  __builtin_popcount check gates the clamp to a
	 * non-pow2 page_size (e.g. a mid-init garbage read), so the align
	 * math stays valid. */
	page_align = (uint64_t)page_size;
	if (page_align == 0 || __builtin_popcountll(page_align) != 1)
		page_align = 4096UL;
	if (c <= (uint64_t)~0ULL - (page_align - 1UL)) {
		cand = (c + page_align - 1UL) & ~(page_align - 1UL);
		if (cand != live_val)
			differs = true;
	}

	if (differs)
		__atomic_fetch_add(&kcov_shm->cmp_hyp_pow2_derive_would_win,
				   1UL, __ATOMIC_RELAXED);
}

/*
 * SHADOW BITMASK combination derive-class measurement.  The live
 * BITMASK lane in cmp_hyp_derive_value() emits a SINGLE bit chosen
 * uniformly from picked->mask (the accumulated OR of every single-bit
 * constant observed at (nr, cmp_ip, width) by cmp_hyp_observe -- the
 * per-hypothesis short-window "pair tracker" this class needs is
 * already materialised in picked->mask because observations at the
 * same (nr, cmp_ip, width) fold into the SAME BITMASK entry).  Two
 * combination probes carry information the single-bit lane cannot:
 *
 *  FULL_OR (would-fire on popcount(mask) >= 2, would-win when the OR
 *  differs from the single bit the live lane just emitted): the OR
 *  of all observed single-bit constants.  Reaches predicates of the
 *  form `(flags & A) && (flags & B)` -- both arms need both bits set
 *  simultaneously, and a lane that only ever fires ONE bit at a time
 *  hits AT MOST one arm per probe.
 *
 *  ANDNOT_TOGGLE (would-fire on popcount(~mask & width_mask) in
 *  [1, 8], would-win when at least one toggled candidate differs
 *  from the live-emitted single bit): treat the observed single-bit
 *  set as the "allowed" bit mask of an `x & ~c` predicate.  The
 *  complement within the operand width is the disallowed-bit mask
 *  c -- toggling each set bit in c one at a time surfaces WHICH
 *  disallowed bit trips the gate.  The 1..8 popcount gate keeps the
 *  candidate set small (a 64-bit width with no observations would
 *  otherwise produce 64 candidates and swamp the measurement) and
 *  restricts the class to sites where the "few disallowed bits"
 *  shape is plausible -- if the complement is dense, the site is
 *  more likely EXACT / ENUM_FAMILY-shaped and the existing lanes
 *  already cover it.
 *
 * Termination stop-condition prose (baked into the shadow gate
 * intentionally): FULL_OR is kept shadow-only in this change even
 * on a large would-win ratio because a lane that always emits the
 * SAME picked->mask on every fire at a given site would only
 * reproduce already-seen edges once the combo gate behind the mask
 * has converted, so a live promotion needs a follow-up feedback-
 * loop input (per-hypothesis pc_win credit on the OR probe) to
 * confirm the combo gate exists at all before it can be judged.
 * ANDNOT_TOGGLE is kept shadow-only for the mirror reason: without
 * per-bit credit attribution the toggle sweep would fire the same
 * candidate ladder every time regardless of which disallowed bit
 * was actually the tripping one.  These counters size the coverage
 * headroom of both classes; the live promotion decision is a
 * follow-up.
 *
 * Bug-pattern guards:
 *   * width_mask computed via the same >=8 short-circuit the
 *     BOUNDARY arm uses (a picked->width of 8 covers the full
 *     uint64, so the (1<<64) shift is skipped -- would be UB).
 *   * disallowed-bit iteration walks bits 0..63 with an explicit
 *     mask test rather than shifting a running bit until wrap; on a
 *     torn read of picked->width, a 0 width_mask yields disallowed
 *     == 0 and the loop simply does not fire the would-win path
 *     (the would-fire gate above already needs popcount >= 1).
 *   * a would-fire that finds no differing toggle candidate does
 *     NOT bump would-win, so the live-lane single-bit picks that
 *     the toggle set happens to hit (e.g. mask == 0x01 and picked
 *     bit == 0x01, toggle over disallowed bit 1 yields 0x03 which
 *     obviously differs) are not double-counted -- the FIRST
 *     differing candidate is enough evidence.
 */
static void cmp_hyp_bitmask_shadow_probe(const struct cmp_hypothesis *picked,
					 unsigned long live_out)
{
	uint64_t mask, width_mask, disallowed, cand;
	uint64_t live_val;
	unsigned int mask_pop, disallowed_pop;
	unsigned int bit_idx;
	bool andnot_differs;

	if (kcov_shm == NULL || picked == NULL)
		return;
	if (picked->kind != CMP_HYP_BITMASK)
		return;

	mask = picked->mask;
	if (mask == 0)
		return;

	mask_pop = (unsigned int)__builtin_popcountll(mask);
	live_val = (uint64_t)live_out;

	/* FULL_OR: needs at least two distinct observed bits, else the
	 * OR degenerates to the same single bit the live lane emits. */
	if (mask_pop >= 2) {
		__atomic_fetch_add(
			&kcov_shm->cmp_hyp_bitmask_full_or_would_fire,
			1UL, __ATOMIC_RELAXED);
		if (mask != live_val)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_bitmask_full_or_would_win,
				1UL, __ATOMIC_RELAXED);
	}

	/* ANDNOT_TOGGLE: width_mask via the same >=8 short-circuit the
	 * BOUNDARY arm uses so a picked->width of 8 does not shift by
	 * 64 (UB). */
	width_mask = (picked->width >= 8)
		? ~(uint64_t)0
		: ((uint64_t)1 << (picked->width * 8)) - 1;
	disallowed = (~mask) & width_mask;
	disallowed_pop = (unsigned int)__builtin_popcountll(disallowed);
	if (disallowed_pop < 1 || disallowed_pop > 8)
		return;

	__atomic_fetch_add(
		&kcov_shm->cmp_hyp_bitmask_andnot_toggle_would_fire,
		1UL, __ATOMIC_RELAXED);

	andnot_differs = false;
	for (bit_idx = 0; bit_idx < 64; bit_idx++) {
		uint64_t bit = (uint64_t)1 << bit_idx;

		if ((disallowed & bit) == 0)
			continue;
		cand = mask | bit;
		if (cand != live_val) {
			andnot_differs = true;
			break;
		}
	}
	if (andnot_differs)
		__atomic_fetch_add(
			&kcov_shm->cmp_hyp_bitmask_andnot_toggle_would_win,
			1UL, __ATOMIC_RELAXED);
}

/*
 * Derive ONE candidate value from PICKED via the spec's ladder.  Every
 * derived value is constructed so cmp_hyp_find_for_credit() will
 * re-resolve back to a hypothesis at the same (cmp_ip, width) at
 * credit time -- either the SAME hypothesis (EXACT.exemplar matches
 * EXACT; ENUM_FAMILY exemplar / lo / hi all lie in [lo, hi]; BITMASK
 * single set-bit is single-bit AND set in mask; RANGE lo / hi /
 * midpoint all lie in [lo, hi]) or, for the EXACT +/-1 arms, the
 * co-populated BOUNDARY hypothesis at the same (cmp_ip, width) via
 * its +/-2 credit window.  For RANGE, boundary probes (lo-1, hi+1)
 * are deliberately NOT emitted -- they fall outside [lo, hi] and so
 * are unreachable by the value-keyed credit walk, which would
 * silently drop their attribution; that neighbourhood is instead the
 * BOUNDARY arm's job.  The EXACT arm's +/-1 rotation is safe because
 * BOUNDARY co-registers on every observation and its credit window
 * (CMP_HYP_BOUNDARY_CREDIT_WINDOW == 2) is wide enough to cover the
 * shifted values.
 *
 * Bug-pattern rules applied:
 *   * midpoint computed as lo + ((hi - lo) >> 1) so (lo + hi) cannot
 *     overflow.
 *   * RANGE rejects hi < lo (a torn read of an in-flight RANGE entry
 *     would otherwise underflow).
 *   * BITMASK with mask == 0 falls back to exemplar so the
 *     popcount-walk loop is never entered with an empty mask.
 *   * popcount-walk bounds via __builtin_popcountll so the bit-pick
 *     index is in [0, popcount); the for-loop's bit shift terminates
 *     on the uint64_t high-bit wrap and the seen counter exits
 *     deterministically.
 */
static bool cmp_hyp_derive_value(const struct cmp_hypothesis *picked,
				 enum cmp_hint_callsite callsite,
				 unsigned long *out)
{
	uint64_t lo, hi, mask;
	unsigned int popcount, pick, seen;
	uint64_t bit;
	enum cmp_hyp_probe_class cls;

	if (picked == NULL || out == NULL)
		return false;
	switch (picked->kind) {
	case CMP_HYP_EXACT: {
		/*
		 * Rotate uniformly among {N-1, N, N+1}, mirroring
		 * cmp_hint_apply_transform's CMP_HINT_BOUNDARY case.
		 * Before this rotation the derive always returned the
		 * exemplar unchanged -- the compile-time const the kernel
		 * had already observed -- so every LIVE typed EXACT inject
		 * re-fed the site the byte-identical value that got recorded
		 * there in the first place: the equality gate the const
		 * originally passed still passed, but strict-inequality
		 * gates ("x < N", "x > N", the pattern documented in the
		 * CMP_HYP_BOUNDARY block below and in include/kcov.h's
		 * cmp_hyp_boundary_* commentary) stayed unsatisfied and
		 * pc_wins was structurally starved on this arm.  The raw
		 * cmp-hint arm applies this same +/-1 rotation at the same
		 * callsites via cmp_hint_apply_transform's CMP_HINT_BOUNDARY
		 * case, so pre-rotation the LIVE typed EXACT arm was a
		 * strict downgrade of the raw arm's conversion (the raw
		 * arm's own comment at the transform notes "the equality
		 * slot -- C unchanged -- is retained in the rotation, so
		 * the worst case is a 3x slowdown on a purely
		 * equality-dominated callsite, while
		 * length-/cap-/extent-dominated syscalls ... get the
		 * boundary edges they were missing").  The rotation restores
		 * parity with the raw arm and lets the strict-inequality
		 * boundary gates convert on the typed arm too.
		 *
		 * Credit attribution: EXACT's find_for_credit arm demands
		 * exemplar == value, so the +/-1 probes do NOT re-resolve
		 * back to this EXACT hypothesis at credit time -- they fall
		 * through to the BOUNDARY arm's +/-2 credit window
		 * (CMP_HYP_BOUNDARY_CREDIT_WINDOW == 2) and get attributed
		 * to whichever BOUNDARY entry the observe path registered
		 * at the same (cmp_ip, width).  Both EXACT and BOUNDARY
		 * co-populate on every observation (see cmp_hyp_observe),
		 * so a fired shifted probe has a home; if the BOUNDARY
		 * slot was reclaimed, per-hypothesis credit misses but the
		 * pc_win itself is still counted in the flat kcov_shm
		 * rollup.  The exemplar arm still re-resolves to this
		 * EXACT hypothesis exactly as before.
		 *
		 * Unsigned wrap at the extremes (N == 0 -> N-1 ==
		 * ULONG_MAX; N == ULONG_MAX -> N+1 == 0) is intentional
		 * and unclamped, matching the raw transform's rationale:
		 * both wrapped values are themselves useful probes
		 * (underflow exercises length-cap validators; overflow
		 * exercises zero-length rejection paths), and the
		 * downstream accept-range gate in cmp_hints_try_get_ex
		 * rejects any that overshoot the caller's bounds and
		 * counts them under
		 * CMP_HYP_LIVE_INJECT_REASON_ACCEPT_REJECT.
		 *
		 * Probe-class histogram: the +/-1 arms bump the shared
		 * CMP_HYP_PROBE_CLASS_BOUNDARY_MINUS1 / _PLUS1 buckets by
		 * *probe shape* rather than by originating hypothesis --
		 * a "constant nudged down/up by 1" probe reached the
		 * kernel, which is what a downstream reader wants to
		 * measure.  Splitting these into dedicated
		 * EXACT_MINUS1 / _PLUS1 buckets would need an
		 * include/kcov.h enum extension deferred to a follow-up if
		 * the shared bucket becomes ambiguous in practice.
		 */
		uint64_t n = picked->exemplar;

		switch (rnd_modulo_u32(3)) {
		case 0:
			*out = (unsigned long)(n - 1);
			cls = CMP_HYP_PROBE_CLASS_BOUNDARY_MINUS1;
			goto out_bump;
		case 2:
			*out = (unsigned long)(n + 1);
			cls = CMP_HYP_PROBE_CLASS_BOUNDARY_PLUS1;
			goto out_bump;
		/* case 1 (and default): N unchanged.  Retains the exact
		 * equality-gate probe so equality-dominated callsites
		 * (cmd codes, enum selectors, version magics) keep
		 * converting on the typed arm. */
		default:
			*out = (unsigned long)n;
			cls = CMP_HYP_PROBE_CLASS_EXACT_EXEMPLAR;
			goto out_bump;
		}
	}
	case CMP_HYP_ENUM_FAMILY:
		switch (rnd_modulo_u32(3)) {
		case 0:
			*out = (unsigned long)picked->exemplar;
			cls = CMP_HYP_PROBE_CLASS_ENUM_EXEMPLAR;
			goto out_bump;
		case 1:
			*out = (unsigned long)picked->lo;
			cls = CMP_HYP_PROBE_CLASS_ENUM_LO;
			goto out_bump;
		default:
			*out = (unsigned long)picked->hi;
			cls = CMP_HYP_PROBE_CLASS_ENUM_HI;
			goto out_bump;
		}
	case CMP_HYP_BITMASK:
		mask = picked->mask;
		if (mask == 0) {
			*out = (unsigned long)picked->exemplar;
			cls = CMP_HYP_PROBE_CLASS_EXEMPLAR_FALLBACK;
			goto out_bump;
		}
		popcount = (unsigned int)__builtin_popcountll(mask);
		pick = rnd_modulo_u32(popcount);
		seen = 0;
		for (bit = 1; bit != 0; bit <<= 1) {
			if ((mask & bit) == 0)
				continue;
			if (seen == pick) {
				*out = (unsigned long)bit;
				cls = CMP_HYP_PROBE_CLASS_BITMASK_SINGLE_BIT;
				goto out_bump;
			}
			seen++;
		}
		/* Unreachable: popcount of a non-zero mask is in
		 * [1, 64], and pick < popcount.  Fall back to exemplar so
		 * a future bit-shape change cannot strand the inject. */
		*out = (unsigned long)picked->exemplar;
		cls = CMP_HYP_PROBE_CLASS_EXEMPLAR_FALLBACK;
		goto out_bump;
	case CMP_HYP_RANGE:
		lo = picked->lo;
		hi = picked->hi;
		if (hi < lo)
			return false;
		switch (rnd_modulo_u32(3)) {
		case 0:
			*out = (unsigned long)lo;
			cls = CMP_HYP_PROBE_CLASS_RANGE_LO;
			goto out_bump;
		case 1:
			*out = (unsigned long)hi;
			cls = CMP_HYP_PROBE_CLASS_RANGE_HI;
			goto out_bump;
		default:
			*out = (unsigned long)(lo + ((hi - lo) >> 1));
			cls = CMP_HYP_PROBE_CLASS_RANGE_MIDPOINT;
			goto out_bump;
		}
	case CMP_HYP_BOUNDARY: {
		/*
		 * Neighbourhood ladder around the exemplar N: the strict-
		 * inequality boundary EXACT cannot pass (the passing value
		 * for `x < N` is N-1, for `x > N` is N+1) and RANGE refuses
		 * to emit (the comment at RANGE bans lo-1 / hi+1 because the
		 * value-keyed credit walk cannot re-resolve them; the lane
		 * here owns that emission and the BOUNDARY arm of
		 * cmp_hyp_find_for_credit() owns the matching credit walk).
		 *
		 * Bug-pattern guards from the audit batch:
		 *   * unsigned underflow: emit N-1 / N-2 only when N >= 1
		 *     / N >= 2; arg1 is u64, N=0 - 1 would otherwise land at
		 *     ULONG_MAX.
		 *   * width overflow: skip the + arms when N is at the
		 *     width's max (1 << (width*8) - 1) so a u8/u16 boundary
		 *     does not wrap to 0 (or, worse, leak high-bit garbage
		 *     past the operand width that the accept gate would then
		 *     reject anyway).
		 *   * mask the derived value to the operand width so an u8
		 *     boundary at value 255 with the +1 arm gated off still
		 *     yields a well-formed 8-bit value when the sweep arm
		 *     touches it.
		 * The accept-range gate in cmp_hints_try_get_ex (and the
		 * caller's own range check) is the second line of defence:
		 * a derived neighbour past the caller's bounds is rejected
		 * cleanly and counted under
		 * CMP_HYP_LIVE_INJECT_REASON_ACCEPT_REJECT.
		 */
		uint64_t n = picked->exemplar;
		uint64_t width_mask = (picked->width >= 8)
			? ~(uint64_t)0
			: ((uint64_t)1 << (picked->width * 8)) - 1;
		uint64_t width_max = width_mask;
		uint64_t cand;
		bool have_cand = false;

		switch (rnd_modulo_u32(4)) {
		case 0:
			if (n >= 1) {
				cand = n - 1;
				cls = CMP_HYP_PROBE_CLASS_BOUNDARY_MINUS1;
				have_cand = true;
				break;
			}
			/* N=0: N-1 would underflow.  Fall through to the +1
			 * arm which is well-defined for N=0 at any width. */
			/* fallthrough */
		case 1:
			if (n < width_max) {
				cand = n + 1;
				cls = CMP_HYP_PROBE_CLASS_BOUNDARY_PLUS1;
				have_cand = true;
				break;
			}
			/* N == width_max: N+1 would overflow the operand
			 * width.  Fall through to the exemplar arm, which
			 * always fits. */
			/* fallthrough */
		case 2:
			cand = n;
			cls = CMP_HYP_PROBE_CLASS_BOUNDARY_EXACT;
			have_cand = true;
			break;
		default:
			/* Widen-by-one sweep for off-by-one chains.  Random
			 * direction; the same underflow / overflow guards as
			 * the +/-1 arms apply at the wider step. */
			if (rnd_modulo_u32(2) == 0) {
				if (n >= 2) {
					cand = n - 2;
					cls = CMP_HYP_PROBE_CLASS_BOUNDARY_SWEEP;
					have_cand = true;
					break;
				}
			} else {
				if (n + 2 > n && n + 2 <= width_max) {
					cand = n + 2;
					cls = CMP_HYP_PROBE_CLASS_BOUNDARY_SWEEP;
					have_cand = true;
					break;
				}
			}
			/* Both sweep directions strand the value at this
			 * width.  Fall back to the exemplar so the lane never
			 * emits "no value" -- the find_for_credit BOUNDARY
			 * window covers exemplar matches too. */
			cand = n;
			cls = CMP_HYP_PROBE_CLASS_BOUNDARY_EXACT;
			have_cand = true;
			break;
		}
		if (!have_cand)
			return false;
		*out = (unsigned long)(cand & width_mask);
		goto out_bump;
	}
	default:
		return false;
	}

out_bump:
	/* SHADOW: census which probe class the derivation just emitted.
	 * Pure observation -- *out is unchanged from the pre-census ladder,
	 * the live inject arm receives the same byte-identical value. */
	if (kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->cmp_hyp_probe_class_hist[cls],
				   1UL, __ATOMIC_RELAXED);

	/* SHADOW: pow2 / alignment probe-class would-fire / would-win
	 * measurement.  Gated on a size / offset-class callsite and a
	 * near-pow2 exemplar; compares the value the live derive just
	 * wrote to *out against the pow2 / align candidate set without
	 * mutating it.  The live derive path (and every downstream
	 * caller of cmp_hyp_derive_value) is byte-for-byte unchanged. */
	cmp_hyp_pow2_shadow_probe(picked, callsite, *out);

	/* SHADOW: bitmask FULL_OR / ANDNOT_TOGGLE would-fire / would-win
	 * measurement.  Gated on picked->kind == CMP_HYP_BITMASK inside
	 * the helper; picked->mask carries the per-(nr, cmp_ip, width)
	 * accumulated OR of all single-bit constants observed at this
	 * site, so no extra pair state is needed.  Nothing else is
	 * touched -- *out and the probe-class histogram bump above are
	 * unchanged. */
	cmp_hyp_bitmask_shadow_probe(picked, *out);
	return true;
}

/*
 * LIVE typed-hypothesis inject try.  Composes the conservative gate
 * (plateau == CMP_RISING_PC_FLAT AND ONE_IN(4)) with the shadow
 * resolver and the derive helper above.  On a fire the raw pool's
 * (cmp_ip, value, width) tuple the pick step computed is replaced by
 * (cmp_ip, derived, width) -- cmp_ip and width are unchanged because
 * the inject targets the SAME comparison site, just substituting a
 * typed-derived value for the raw replay.
 *
 * The caller (cmp_hints_try_get_ex) only invokes this on a typed-safe
 * argtype; gating that here would conflate the gate's "did not fire"
 * with the caller's "not eligible" cohort.
 *
 * Per-pull accounting is deferred to the caller's accept-gated commit
 * point so a hint the caller's accept range subsequently rejects does
 * not contaminate cmp_hyp_live_inject_gate_passed /
 * cmp_hyp_live_injected[/_by_kind].  This helper bumps nothing, and
 * signals back through two out-params:
 *
 *   *out_gate_fired -- the conservative gate passed (plateau + dice +
 *                      size + shm); the caller bumps gate_passed when
 *                      its accept gate also passes.  Preserves the
 *                      "gate fired but the typed store had nothing"
 *                      observability the gate_passed - live_injected
 *                      delta currently surfaces, just gated on the
 *                      value actually reaching the consumer.
 *   *out_kind       -- picked->kind, valid iff the function returns
 *                      true (i.e. picked != NULL AND derive
 *                      succeeded).  The caller bumps live_injected /
 *                      live_injected_by_kind[*out_kind] under the
 *                      same accept-gate.
 *
 * Both out-params are written on every entry: out_gate_fired starts
 * at false and only flips true once the gate passes, out_kind is left
 * at 0 unless the function returns true.  Callers can therefore key
 * their accounting off the bool return alone for live_injected and off
 * *out_gate_fired for gate_passed without re-checking helper inputs.
 */
bool cmp_hyp_try_live_inject(unsigned int nr, bool do32,
			     unsigned long cmp_ip, unsigned int size,
			     unsigned int arg_idx __attribute__((unused)),
			     enum cmp_hint_callsite callsite,
			     unsigned long *out,
			     uint8_t *out_kind,
			     bool *out_gate_fired)
{
	struct cmp_hyp_pool *pool;
	struct cmp_hypothesis *picked;
	bool present[CMP_HYP_KIND_NR];
	uint8_t width;
	unsigned long derived;
	bool plateau_on;
	bool channel_a_fired;
	bool channel_b_fired = false;
	bool channel_c_dice_won = false;
	uint8_t picked_state;

	*out_gate_fired = false;
	*out_kind = 0;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return false;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		return false;
	if (shm == NULL)
		return false;

	/*
	 * Three independent channels can open this gate:
	 *
	 *   A  plateau == CMP_RISING_PC_FLAT  AND  ONE_IN(LIVE_INJECT_DENOM)
	 *   B  ONE_IN(BOOTSTRAP_DENOM)                          (always-on)
	 *   C  ONE_IN(PROMOTED_DENOM)  AND  picker returns PROMOTED
	 *
	 * A is the historical plateau-amplified path; the bootstrap (B) and
	 * promoted-bypass (C) channels exist so PC wins can accumulate even
	 * when the plateau gate has never opened.  C's "picker returns
	 * PROMOTED" half is verified AFTER the pool walk further down -- we
	 * roll the dice here and consult the picker once, deferring channel
	 * attribution until we know whether C qualifies.
	 *
	 * Dice are rolled even when an earlier channel has already fired so
	 * the random stream stays callsite-deterministic across plateau
	 * transitions -- without this, flipping the plateau on / off would
	 * shift every downstream rnd_*() consumer's value.  Cost is two
	 * rnd_modulo_u32 calls in the rejected case, both off the hot raw
	 * cmp-hint path.
	 */
	plateau_on = (__atomic_load_n(&shm->plateau_current_hypothesis,
				      __ATOMIC_RELAXED) ==
		      (int)PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT);
	channel_a_fired = plateau_on && ONE_IN(CMP_HYP_LIVE_INJECT_DENOM);
	if (ONE_IN(CMP_HYP_LIVE_INJECT_BOOTSTRAP_DENOM))
		channel_b_fired = true;
	if (ONE_IN(CMP_HYP_LIVE_INJECT_PROMOTED_DENOM))
		channel_c_dice_won = true;

	if (!channel_a_fired && !channel_b_fired && !channel_c_dice_won) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_inject_reason[plateau_on
					? CMP_HYP_LIVE_INJECT_REASON_DICE_MISS
					: CMP_HYP_LIVE_INJECT_REASON_NOT_PLATEAU],
				1UL, __ATOMIC_RELAXED);
		return false;
	}

	*out_gate_fired = true;

	width = (uint8_t)size;
	pool = &cmp_hints_shm->hyp_pools[nr][do32 ? 1 : 0];

	picked = cmp_hyp_would_pick_locked(pool, cmp_ip, width, present);
	if (picked == NULL) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_NO_MATCH],
				1UL, __ATOMIC_RELAXED);
		return false;
	}

	/*
	 * Channel attribution.  Priority C > B > A: PROMOTED_BYPASS is the
	 * most informative signal (state machine validated the hyp), so when
	 * channels overlap we credit the most specific one.  Channel A has
	 * no specific reason counter -- its firings are visible as
	 * cmp_hyp_live_inject_gate_passed minus the sum of the BOOTSTRAP and
	 * PROMOTED_BYPASS reason counters.
	 *
	 * The "channel C dice won but picked is not PROMOTED, and A/B both
	 * lost" branch bails via NO_MATCH: structurally there IS a
	 * hypothesis at the site (picker returned non-NULL), but no channel
	 * actually qualified to drive an inject -- C requires PROMOTED, B/A
	 * didn't roll.  Treating it as NO_MATCH keeps the per-reason
	 * partition closed (sum of head + downstream reasons + injected ==
	 * total entries past the size-class guard) without adding a third
	 * new enum value just for this one corner.
	 */
	picked_state = __atomic_load_n(&picked->state, __ATOMIC_RELAXED);
	if (channel_c_dice_won && picked_state == CMP_HYP_STATE_PROMOTED) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_PROMOTED_BYPASS],
				1UL, __ATOMIC_RELAXED);
	} else if (channel_b_fired) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_BOOTSTRAP],
				1UL, __ATOMIC_RELAXED);
	} else if (!channel_a_fired) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_NO_MATCH],
				1UL, __ATOMIC_RELAXED);
		return false;
	}

	if (!cmp_hyp_derive_value(picked, callsite, &derived)) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_DERIVE_FAIL],
				1UL, __ATOMIC_RELAXED);
		return false;
	}

	*out = derived;
	*out_kind = picked->kind;
	return true;
}
