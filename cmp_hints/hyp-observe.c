/*
 * SHADOW typed-hypothesis observe path.
 *
 * Split out of hyp.c so the EXACT / BITMASK / ENUM_FAMILY / RANGE /
 * BOUNDARY kind-lane inference lives in its own translation unit,
 * separate from credit / pick / derive / live.  Uses the shared
 * pool primitives declared in cmp_hints/hyp-internal.h.
 */

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "cmp_hints/hyp-internal.h"
#include "kcov.h"
#include "shm.h"

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
			__atomic_fetch_add(&kcov_shm->cmp_hyp_results.cmp_hyp_pool_overflow, 1UL,
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
					&kcov_shm->cmp_hyp_results.cmp_hyp_boundary_inserted,
					1UL, __ATOMIC_RELAXED);
		}
	}
}
