/*
 * SHADOW typed-hypothesis picker.
 *
 * Split out of hyp.c: the value-agnostic pool walk
 * (cmp_hyp_would_pick_locked) plus the SHADOW would-pick wrapper
 * invoked by cmp_hints_try_get_ex() on every successful raw-pool
 * pick.  The picker's specificity ordering (EXACT > ENUM_FAMILY >
 * BITMASK > RANGE > BOUNDARY) matches cmp_hyp_find_for_credit; the
 * state-aware preference within each kind (PROMOTED > OBSERVED >
 * DEMOTED via reroll) is documented at the function header below.
 *
 * cmp_hyp_would_pick_locked drops static because the live inject arm
 * in hyp-live.c consumes it; declaration lives in
 * cmp_hints/hyp-internal.h.
 */

#include <stdint.h>

#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "cmp_hints/hyp-internal.h"
#include "kcov.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "utils.h"

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
struct cmp_hypothesis *
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
					&kcov_shm->cmp_hyp_results.cmp_hyp_skipped_retired_by_kind[h->kind],
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
					&kcov_shm->cmp_hyp_results.cmp_hyp_picked_by_state[CMP_HYP_STATE_PROMOTED], \
					1UL, __ATOMIC_RELAXED);		\
			return (p);					\
		}							\
		if ((o) != NULL) {					\
			if (kcov_shm != NULL)				\
				__atomic_fetch_add(			\
					&kcov_shm->cmp_hyp_results.cmp_hyp_picked_by_state[CMP_HYP_STATE_OBSERVED], \
					1UL, __ATOMIC_RELAXED);		\
			return (o);					\
		}							\
		if ((d) != NULL && ONE_IN(CMP_HYP_DEMOTED_RETRY_DENOM)) { \
			if (kcov_shm != NULL) {				\
				__atomic_fetch_add(			\
					&kcov_shm->cmp_hyp_results.cmp_hyp_picked_by_state[CMP_HYP_STATE_DEMOTED], \
					1UL, __ATOMIC_RELAXED);		\
				__atomic_fetch_add(			\
					&kcov_shm->cmp_hyp_results.cmp_hyp_demoted_reroll_picked_by_kind[(d)->kind], \
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
		__atomic_fetch_add(&kcov_shm->cmp_hyp_results.cmp_hyp_boundary_candidate_available,
				   1UL, __ATOMIC_RELAXED);
}
