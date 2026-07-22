#pragma once

/* Sub-struct of struct kcov_shared, embedded as .cmp_hyp_lifecycle.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_cmp_hyp_lifecycle {
unsigned long cmp_hyp_inserted_by_kind[CMP_HYP_KIND_NR];

/* Per-kind flat census of typed CMP hypothesis insert rejections
 * caused by the per-kind sub-cap (CMP_HYP_PER_KIND).  Bumped in
 * lock-step with the scalar cmp_hyp_kind_full from cmp_hyp_alloc()'s
 * per-kind-exhausted branch, so the sum across kinds equals
 * cmp_hyp_kind_full modulo concurrent sampling.  Paired with
 * cmp_hyp_inserted_by_kind above this shows, per kind, the
 * accepted-vs-dropped split -- i.e. which kind is eating the cap
 * when cmp_hyp_kind_full dominates.  SHADOW telemetry only -- no
 * consumer reads it. */
unsigned long cmp_hyp_kind_full_by_kind[CMP_HYP_KIND_NR];

/* Per-kind flat census of typed CMP hypothesis consumes.
 * Bumped in lock-step with the scalar cmp_hyp_consumed above
 * from the cmp_hyp_credit_consume() hit path, so the sum across
 * kinds equals cmp_hyp_consumed modulo concurrent sampling.
 * The per-hypothesis consumed_count is per-entry; this flat
 * array is the persistent fleet mirror.  Paired with
 * cmp_hyp_inserted_by_kind this shows, per kind, the share of
 * insertions the typed consumer is actually pulling.  SHADOW
 * telemetry only -- no consumer reads it. */
unsigned long cmp_hyp_consumed_by_kind[CMP_HYP_KIND_NR];

/*
 * SHADOW would-pick telemetry resolved alongside each successful
 * raw cmp_hints_try_get_ex() return.  For the same (nr, do32,
 * cmp_ip, width) the raw pool just served, the typed hypothesis
 * store is walked through the same EXACT > ENUM_FAMILY > BITMASK >
 * RANGE specificity ladder cmp_hyp_credit_outcome() uses; the
 * resulting "what would the store have picked" is then bumped into
 * the counters below.  Pure observation -- the live pick is the
 * raw pool value, byte-for-byte unchanged; nothing here is gated
 * by a CLI knob.
 *
 *  cmp_hyp_would_pick_by_kind[k]
 *      Bumped at index k = picked->kind when the ladder resolves
 *      to a hypothesis for (cmp_ip, width).  Sum across kinds is
 *      the per-pick rate at which the typed store has SOMETHING
 *      to say about the comparison sites the raw pool is serving.
 *      Only the four ladder kinds (EXACT, ENUM_FAMILY, BITMASK,
 *      RANGE) ever populate; the other CMP_HYP_KIND_NR slots stay
 *      zero by construction.
 *  cmp_hyp_would_miss_by_kind[k]
 *      Bumped at index k for each ladder kind absent from
 *      (cmp_ip, width) on this pick.  Per raw pick: 0..4 bumps,
 *      one per missing ladder kind, so the per-kind ratio
 *      pick[k] / (pick[k] + miss[k]) reports the typed store's
 *      per-kind coverage of the served comparison sites.  Same
 *      four-slot population rule as the pick counter.
 *  cmp_hyp_would_value_differs
 *      Bumped when the ladder resolves to a hypothesis whose
 *      exemplar is not equal to the raw pool's picked value --
 *      the store would have suggested a different concrete value
 *      for the same site.  Scalar headline; the per-kind drilldown
 *      lives in cmp_hyp_would_value_differs_by_kind below.
 *  cmp_hyp_would_value_differs_by_kind[k]
 *      Per-kind partition of cmp_hyp_would_value_differs, bumped
 *      at index k = picked->kind in lock-step with the scalar from
 *      the same cmp_hyp_would_pick() site.  Sum across kinds equals
 *      the scalar modulo concurrent sampling.  Only the kinds that
 *      the ladder can resolve to (EXACT, ENUM_FAMILY, BITMASK,
 *      RANGE, BOUNDARY) ever populate; the remaining CMP_HYP_KIND_NR
 *      slots stay zero by construction.  Paired with
 *      cmp_hyp_would_pick_by_kind the ratio
 *      value_differs_by_kind[k] / would_pick_by_kind[k] is the
 *      per-kind rate at which the typed store's exemplar disagrees
 *      with the raw-pool pick -- surfaces which hypothesis kind is
 *      most often carrying a value the live path would not have
 *      served.  SHADOW telemetry only -- no consumer reads it.
 */
unsigned long cmp_hyp_would_pick_by_kind[CMP_HYP_KIND_NR];
unsigned long cmp_hyp_would_miss_by_kind[CMP_HYP_KIND_NR];
unsigned long cmp_hyp_would_value_differs;
unsigned long cmp_hyp_would_value_differs_by_kind[CMP_HYP_KIND_NR];

/*
 * LIVE typed-hypothesis inject counters.  Bumped from the inject
 * arm in cmp_hints_try_get_ex() so the inject rate is legible
 * alongside the would-pick / would-value-differs shadow rates
 * above.  Pure observability -- the inject arm's gate
 * (plateau == CMP_RISING_PC_FLAT AND ONE_IN(32)) and the
 * typed-safe caller opt-in are what actually scope the rate.
 *
 *  cmp_hyp_live_injected
 *      Total stash entries the live inject arm produced.  The
 *      ratio cmp_hyp_live_injected / cmp_hints_consumed is the
 *      fleet-level fraction of consumed hints whose value came
 *      from a typed hypothesis rather than the raw pool.
 *  cmp_hyp_live_injected_by_kind[k]
 *      Per-kind partition of the above.  Sum across kinds
 *      equals cmp_hyp_live_injected modulo concurrent sampling.
 *      Only the four ladder kinds (EXACT, ENUM_FAMILY, BITMASK,
 *      RANGE) ever populate; the other CMP_HYP_KIND_NR slots
 *      stay zero by construction.
 *  cmp_hyp_live_inject_gate_passed
 *      Total times the conservative gate (plateau AND ONE_IN(32))
 *      passed.  Paired with cmp_hyp_live_injected gives the
 *      gate-passed-but-no-hypothesis rate (gate_passed minus
 *      injected = empty-resolver bails), separating "the arm
 *      did not fire" from "the arm fired but the store had
 *      nothing to say at the served site".
 */
unsigned long cmp_hyp_live_injected;
unsigned long cmp_hyp_live_injected_by_kind[CMP_HYP_KIND_NR];
unsigned long cmp_hyp_live_inject_gate_passed;

/*
 * Per-reason close counters for the LIVE inject path.  Indexed by
 * enum cmp_hyp_live_inject_reason (include/cmp_hints.h).  Each
 * early-return / reject site on the inject path bumps exactly one
 * slot, so the sum across slots + cmp_hyp_live_injected equals the
 * total times the inject arm was entered with a typed-eligible
 * caller.  Disambiguates "gate_passed=0" between "plateau never
 * sat at CMP_RISING_PC_FLAT", "dice never won", "no hypothesis at
 * the served site", "derive bailed", and "accept range rejected
 * the derived value".  Pure observability; the gate logic itself
 * is unchanged.
 */
unsigned long cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_NR];

/* Per-kind flat census of typed CMP hypothesis insert rejections
 * caused by the per-syscall total cap (CMP_HYP_PER_SYSCALL).  Bumped
 * in lock-step with the scalar cmp_hyp_pool_full from cmp_hyp_alloc()'s
 * per-syscall-exhausted branch -- the sole bumper of cmp_hyp_pool_full.
 * The cmp_hyp_observe() corruption bail bumps the sibling
 * cmp_hyp_pool_overflow counter, so the sum across kinds equals
 * cmp_hyp_pool_full modulo concurrent sampling.  Paired with
 * cmp_hyp_inserted_by_kind this shows, per kind, which kind is
 * consuming the per-syscall budget when cmp_hyp_pool_full dominates.
 * SHADOW telemetry only -- no consumer reads it. */
unsigned long cmp_hyp_pool_full_by_kind[CMP_HYP_KIND_NR];
};
