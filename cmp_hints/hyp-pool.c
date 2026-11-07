/*
 * SHADOW typed-hypothesis pool primitives: find / alloc / RANGE inference,
 * shared by the lane files through cmp_hints/hyp-internal.h.  Every writer
 * runs under the matching durable cmp_hint_pool lock, so hyp_pools[nr][do32]
 * is serialised per (nr, do32) without a second lock of its own.
 */

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "cmp_hints/hyp-internal.h"
#include "kcov.h"
#include "shm.h"

struct cmp_hypothesis *cmp_hyp_find(struct cmp_hyp_pool *pool,
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

struct cmp_hypothesis *cmp_hyp_find_exact(struct cmp_hyp_pool *pool,
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
 * Infer a RANGE's direction / signedness / relation-class from the
 * ENUM_FAMILY cluster summary at the same (cmp_ip, width).  KCOV does
 * NOT expose the kernel-side compare operator -- direction is
 * APPROXIMATE.  The heuristic: if the most-recent exemplar sits at the
 * high end of the cluster, treat the probe as ASCENDING (kernel keeps
 * comparing against a rising bound); at the low end, DESCENDING;
 * otherwise UNKNOWN so an un-inferable probe is bucketed honestly
 * rather than force-fit to a guess.
 *
 * Signedness: a u8 hi=0xFF and an s8 hi=-1 are different probes.
 * Conservative classifier: SIGNED if either bound has the width's sign
 * bit set, else UNSIGNED.
 *
 * Relation: only INSIDE is reachable from the observer side -- KCOV
 * gives us matching operand values, not edge-rejection events.  The
 * OUTSIDE / BOUND / WRAP buckets exist for the future consumer-side
 * probe ladder and stay zero here.
 */
void cmp_hyp_range_identity_infer(uint64_t lo, uint64_t hi,
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
 * A slot of KIND for a new hypothesis once the kind or the pool is at its
 * cap: a RETIRED hypothesis's, or else one at a site the durable pool RAW
 * no longer holds, DEMOTED before OBSERVED before PROMOTED.  The live arm
 * injects only at the site of a pick from RAW, so such a hypothesis is
 * out of its reach until the site comes back.  NULL when every slot of
 * KIND that is not RETIRED is at a site RAW holds.
 */
static struct cmp_hypothesis *cmp_hyp_reusable(struct cmp_hyp_pool *pool,
					       enum cmp_hypothesis_kind kind,
					       const struct cmp_hint_pool *raw)
{
	struct cmp_hypothesis *best = NULL;
	unsigned int i, j, rank, best_rank = 0, n = raw->count;

	if (n > CMP_HINTS_PER_SYSCALL)
		return NULL;
	for (i = 0; i < pool->count; i++) {
		struct cmp_hypothesis *h = &pool->entries[i];
		uint8_t state;

		if (h->kind != kind)
			continue;
		state = __atomic_load_n(&h->state, __ATOMIC_RELAXED);
		if (state == CMP_HYP_STATE_RETIRED)
			return h;
		for (j = 0; j < n; j++) {
			if (raw->entries[j].cmp_ip == h->cmp_ip &&
			    raw->entries[j].size == h->width)
				break;
		}
		if (j < n)
			continue;
		rank = state == CMP_HYP_STATE_DEMOTED ? 0 :
		       state == CMP_HYP_STATE_PROMOTED ? 2 : 1;
		if (best == NULL || rank < best_rank) {
			best = h;
			best_rank = rank;
		}
	}
	return best;
}

/*
 * Allocate a hypothesis slot honouring the per-kind sub-cap and the
 * per-syscall total cap: a fresh one while both have room, else one
 * cmp_hyp_reusable() gives up.  Returns NULL when there is neither and
 * bumps the matching kcov_shm saturation counter so the rejection is
 * visible.  The slot is memset and pre-stamped with identity fields
 * the caller does not have to re-write.  Readers walk the pool
 * lock-free, so one can meet a reused slot half-written, as it can an
 * appended one; the picker and the credit check already pass over a
 * torn entry.
 */
struct cmp_hypothesis *cmp_hyp_alloc(struct cmp_hyp_pool *pool,
				     enum cmp_hypothesis_kind kind,
				     unsigned int nr, bool do32,
				     unsigned long cmp_ip, uint8_t width)
{
	bool fresh = pool->count < CMP_HYP_PER_SYSCALL &&
		     pool->per_kind_count[kind] < CMP_HYP_PER_KIND;
	struct cmp_hypothesis *h;

	if (fresh)
		h = &pool->entries[pool->count];
	else
		h = cmp_hyp_reusable(pool, kind,
				     &cmp_hints_shm->pools[nr][do32 ? 1 : 0]);
	if (h == NULL) {
		if (kcov_shm == NULL)
			return NULL;
		if (pool->count >= CMP_HYP_PER_SYSCALL) {
			__atomic_fetch_add(&kcov_shm->hyp_flat.cmp_hyp_pool_full, 1UL,
					   __ATOMIC_RELAXED);
			__atomic_fetch_add(&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_pool_full_by_kind[kind],
					   1UL, __ATOMIC_RELAXED);
		} else {
			__atomic_fetch_add(&kcov_shm->hyp_flat.cmp_hyp_kind_full, 1UL,
					   __ATOMIC_RELAXED);
			__atomic_fetch_add(&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_kind_full_by_kind[kind],
					   1UL, __ATOMIC_RELAXED);
		}
		return NULL;
	}

	memset(h, 0, sizeof(*h));
	h->nr = nr;
	h->do32 = do32;
	h->width = width;
	h->kind = (uint8_t)kind;
	h->state = CMP_HYP_STATE_OBSERVED;
	h->cmp_ip = (uint64_t)cmp_ip;
	if (fresh) {
		pool->per_kind_count[kind]++;
		pool->count++;
	}
	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->hyp_flat.cmp_hyp_inserted, 1UL,
				   __ATOMIC_RELAXED);
		__atomic_fetch_add(&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_inserted_by_kind[kind],
				   1UL, __ATOMIC_RELAXED);
	}
	return h;
}
