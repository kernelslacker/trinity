/*
 * SHADOW typed-hypothesis pool primitives: find / alloc / range-identity.
 *
 * Split out of hyp.c so the observe / credit / pick / derive / live lane
 * files can reach the shared allocation and range-identity helpers via
 * cmp_hints/hyp-internal.h.  Every writer runs under the matching
 * durable cmp_hint_pool lock so hyp_pools[nr][do32] is serialised
 * per-(nr, do32) without a second lock of its own.
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
 * RANGE dedup by inferred identity, NOT cmp_ip: two comparison sites
 * that observe the same logical range probe (same bounds, same
 * inferred direction, same width / signedness / relation-class)
 * collapse to ONE entry, and value churn at a single site that does
 * not shift the bounds folds into the same slot.  Bounds are part of
 * identity rather than payload, so a probe whose bounds drift even
 * one step apart is keyed as a distinct hypothesis.
 */
struct cmp_hypothesis *
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
struct cmp_hypothesis *cmp_hyp_alloc(struct cmp_hyp_pool *pool,
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
