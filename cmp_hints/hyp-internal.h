/*
 * SHADOW typed-hypothesis: private cross-lane prototypes.
 *
 * hyp.c is being split into per-responsibility lane files
 * (hyp-pool.c, hyp-observe.c, hyp-credit.c, hyp-pick.c,
 * hyp-derive.c, hyp-live.c).  Helpers that one lane file exports to
 * a SIBLING lane -- but NOT to the public cmp_hints.h /
 * cmp_hints-internal.h interface -- live here.
 */

#ifndef CMP_HINTS_HYP_INTERNAL_H
#define CMP_HINTS_HYP_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

#include "cmp_hints.h"

/*
 * hyp-pool.c: allocation + identity helpers used by hyp-observe.c.
 * Every writer runs under the matching durable cmp_hint_pool lock so
 * hyp_pools[nr][do32] is serialised per-(nr, do32) without a second
 * lock of its own -- callers are responsible for holding it.
 */
struct cmp_hypothesis *cmp_hyp_find(struct cmp_hyp_pool *pool,
				    enum cmp_hypothesis_kind kind,
				    unsigned long cmp_ip, uint8_t width);
struct cmp_hypothesis *cmp_hyp_find_exact(struct cmp_hyp_pool *pool,
					  unsigned long cmp_ip,
					  uint8_t width, uint64_t value);
struct cmp_hypothesis *cmp_hyp_alloc(struct cmp_hyp_pool *pool,
				     enum cmp_hypothesis_kind kind,
				     unsigned int nr, bool do32,
				     unsigned long cmp_ip, uint8_t width);
void cmp_hyp_range_identity_infer(uint64_t lo, uint64_t hi,
				  uint8_t width,
				  const struct cmp_hypothesis *src,
				  uint8_t *out_dir, uint8_t *out_sign,
				  uint8_t *out_rel);
struct cmp_hypothesis *
cmp_hyp_find_range_by_identity(struct cmp_hyp_pool *pool, uint64_t lo,
			       uint64_t hi, uint8_t width, uint8_t dir,
			       uint8_t sign, uint8_t rel);

/*
 * hyp-pick.c: value-agnostic picker used by hyp-live.c to resolve the
 * candidate hypothesis at (cmp_ip, width).  Writes a CMP_HYP_KIND_NR-
 * wide presence mask through *present_out reflecting which kinds the
 * picker would have CONSIDERED (RETIRED slots do not register).
 */
struct cmp_hypothesis *
cmp_hyp_would_pick_locked(struct cmp_hyp_pool *pool, unsigned long cmp_ip,
			  uint8_t width,
			  bool present_out[CMP_HYP_KIND_NR]);

/*
 * hyp-derive.c: candidate synthesis used by hyp-live.c.  Emits ONE
 * value from the picked hypothesis's ladder and returns whether the
 * emission was constructable (RANGE with hi < lo, unrecognised kind
 * -> false).
 */
bool cmp_hyp_derive_value(const struct cmp_hypothesis *picked,
			  enum cmp_hint_callsite callsite,
			  unsigned long *out);

#endif
