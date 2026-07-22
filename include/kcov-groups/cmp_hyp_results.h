#pragma once

/* Sub-struct of struct kcov_shared, embedded as .cmp_hyp_results.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_cmp_hyp_results {
unsigned long cmp_hyp_pool_overflow;

/*
 * SHADOW promotion-rule eval per cmp_hyp_credit_outcome() landing.
 * After the per-hyp outcome counter and its kcov_shm flat twin are
 * bumped, the credited hypothesis is evaluated against a fixed rule
 * and one of the two arrays is bumped at index h->kind:
 *
 *  cmp_hyp_would_promote_by_kind[k]
 *      Bumped when (pc_wins || transition_wins || corpus_save_wins)
 *      on the credited hyp -- the hyp has produced at least one
 *      attributable conversion and the live promotion path would
 *      mark it CMP_HYP_STATE_PROMOTED.
 *  cmp_hyp_would_demote_by_kind[k]
 *      Bumped when (misses >= 8) AND none of the three win counters
 *      above are set -- repeated consumption with no payoff, which
 *      the live demotion path would mark CMP_HYP_STATE_DEMOTED.
 *      The K=8 threshold matches the per-kind sub-cap order of
 *      magnitude (CMP_HYP_PER_KIND==16); high enough to ignore a
 *      handful of noise misses, low enough to fire inside a single
 *      fuzz window on a genuinely dead hyp.
 *
 * Per credit landing at most one of the two arrays bumps (the two
 * predicates are mutually exclusive); a hyp credited with neither
 * (e.g. a single MISS, or a SKIP family outcome with no wins yet)
 * bumps nothing.  Only the four ladder kinds (EXACT, ENUM_FAMILY,
 * BITMASK, RANGE) ever populate, mirroring the existing _by_kind
 * shadow arrays; the other CMP_HYP_KIND_NR slots stay zero by
 * construction.  SHADOW telemetry only -- the h->state field is
 * NOT mutated; no consumer reads either the array or the state.
 */
unsigned long cmp_hyp_would_promote_by_kind[CMP_HYP_KIND_NR];
unsigned long cmp_hyp_would_demote_by_kind[CMP_HYP_KIND_NR];

/*
 * Picker decision census, indexed by the h->state of the
 * hypothesis the picker returned.  Bumped once per non-NULL
 * return from cmp_hyp_would_pick_locked().  The post-deploy
 * confirmation that the state-aware picker is doing what it
 * should: PROMOTED should dominate once the state machine has
 * warmed up, OBSERVED holds steady on cold sites, and the
 * DEMOTED slot reflects the rare re-roll surfacing.  Sized at
 * the enum's NR cap; only the actually-returnable states
 * (PROMOTED / OBSERVED / DEMOTED -- TESTING is treated as
 * OBSERVED) ever populate. */
unsigned long cmp_hyp_picked_by_state[CMP_HYP_STATE_NR];

/* Pair counters for the RETIRED / DEMOTED re-roll arms of the
 * picker.  cmp_hyp_skipped_retired_by_kind[k] bumps once per
 * RETIRED slot of kind k the picker walked past in
 * cmp_hyp_would_pick_locked();
 * cmp_hyp_demoted_reroll_picked_by_kind[k] bumps when the
 * demoted re-roll gate (1 / CMP_HYP_DEMOTED_RETRY_DENOM)
 * actually fires for a kind-k hypothesis.  Together with
 * cmp_hyp_picked_by_state[DEMOTED] this is the
 * directly-measurable channel for "is RETIRED earning its
 * keep" and "is the re-roll rate sane".  The kind partition
 * lets the periodic dump answer "which hypothesis kind is
 * hoarding RETIRED slots" and "which kind wins the demoted
 * re-roll" without a separate hyp-pool walk. */
unsigned long cmp_hyp_skipped_retired_by_kind[CMP_HYP_KIND_NR];
unsigned long cmp_hyp_demoted_reroll_picked_by_kind[CMP_HYP_KIND_NR];

/*
 * Live h->state transition census.  Bumped once per state
 * mutation from cmp_hyp_credit_outcome() at index
 * [old_state][new_state].  Diagonal slots stay zero (no-op
 * transitions are not bumped).  Pairs with the would_promote /
 * would_demote shadow counters above: the shadow counters
 * report "would the live state machine fire if it existed",
 * the transitions array reports "did the live state machine
 * actually fire".  Sized at the enum's NR cap; entries past
 * the real five-state ladder stay zero by construction. */
unsigned long cmp_hyp_state_transitions[CMP_HYP_STATE_NR][CMP_HYP_STATE_NR];

/* Per-kind outcome partition for the typed-hyp credit channels.
 * Bumped alongside the flat cmp_hyp_pc_wins / _transition_wins /
 * etc.  Lets the periodic dump answer "which hypothesis kind is
 * actually converting" without a separate hyp-pool walk.  SHADOW
 * telemetry only -- no consumer reads it. */
unsigned long cmp_hyp_pc_wins_by_kind[CMP_HYP_KIND_NR];
unsigned long cmp_hyp_transition_wins_by_kind[CMP_HYP_KIND_NR];
unsigned long cmp_hyp_misses_by_kind[CMP_HYP_KIND_NR];
unsigned long cmp_hyp_corpus_save_by_kind[CMP_HYP_KIND_NR];
unsigned long cmp_hyp_destructive_by_kind[CMP_HYP_KIND_NR];
unsigned long cmp_hyp_context_skip_by_kind[CMP_HYP_KIND_NR];
unsigned long cmp_hyp_cmp_novelty_wins_by_kind[CMP_HYP_KIND_NR];

/*
 * SHADOW histogram of the 8-band score_bucket value computed in
 * cmp_hyp_credit_outcome().  Bumped once per credit landing, in
 * lock-step with the h->score_bucket store, using the SAME bucket
 * value just written.  Index k corresponds to band k:
 *
 *   0 idle (wins == 0 && pen == 0)
 *   1 penalty-only       (wins == 0, pen >= 1)
 *   2 heavy net-negative (pen >= wins + 4)
 *   3 slight net-negative (wins < pen < wins + 4)
 *   4 break-even         (wins == pen, both >= 1)
 *   5 small net-positive  (1 <= wins - pen < 4)
 *   6 moderate net-positive (4 <= wins - pen < 16)
 *   7 strong net-positive   (wins - pen >= 16)
 *
 * The if/else ladder above the store is exhaustive over 0..7, so
 * the index is bounded by construction; no clamp is needed.  Pure
 * observability: the bucket value is unchanged, h->state is NOT
 * mutated.
 */
unsigned long cmp_hyp_score_bucket_census[8];

/*
 * SHADOW census of which probe class cmp_hyp_derive_value() emits
 * each time it converts a resolved hypothesis to a concrete value
 * for the LIVE typed-inject arm.  Bumped once per successful
 * derivation, at the branch the function ACTUALLY takes today --
 * boundary probes (lo-1, hi+1) are deliberately not emitted by the
 * derive ladder (see the comment above cmp_hyp_derive_value) and
 * have no class here; adding them would lie about the producer.
 *
 *  EXACT_EXEMPLAR            -- CMP_HYP_EXACT path
 *  ENUM_EXEMPLAR/LO/HI       -- CMP_HYP_ENUM_FAMILY 3-way pick
 *  BITMASK_SINGLE_BIT        -- CMP_HYP_BITMASK popcount-walk hit
 *  EXEMPLAR_FALLBACK         -- BITMASK conservative fallback
 *                               (mask == 0, and the popcount-walk
 *                               post-loop guard).  Counted as its
 *                               own class rather than folded into
 *                               BITMASK_SINGLE_BIT so the share of
 *                               derivations that degrade to the
 *                               exemplar is directly visible.
 *  RANGE_LO/HI/MIDPOINT      -- CMP_HYP_RANGE 3-way pick
 *
 * The hi < lo reject and the default-kind reject return false
 * without emitting a value, so nothing bumps for those.
 *
 * Write-only telemetry: no consumer reads this array yet, no CLI
 * knob gates the derivation, and the derived value the live inject
 * arm receives is byte-identical to the pre-census path.
 */
unsigned long cmp_hyp_probe_class_hist[CMP_HYP_PROBE_CLASS_NR];

/*
 * SHADOW BOUNDARY-lane counters for the inequality-gate angle.
 * EXACT-inject is dead because strict inequalities (x < N, x >= N)
 * cannot pass on the const N itself; the passing value is N+/-1,
 * which neither EXACT nor RANGE will derive.  CMP_HYP_BOUNDARY
 * populates from a SINGLE const observation (no RANGE-style
 * seen>=3 / span<=32 gate) and derives a neighbourhood ladder
 * {N-1, N+1, N, N+/-2} so the boundary-adjacent values reach the
 * kernel.  Pure observability here -- the existing live inject
 * arm's would_pick_locked precedence is unchanged, so BOUNDARY
 * only sees live air when nothing else explains the served site;
 * the counters below are how we measure whether that ever fires.
 *
 *  cmp_hyp_boundary_inserted
 *      Bumped once per fresh CMP_HYP_BOUNDARY allocation in
 *      cmp_hyp_observe().  Proves the population path fires for
 *      single-const inequality sites; staying zero means the lane
 *      is dead before it starts and there is nothing to measure.
 *  cmp_hyp_boundary_candidate_available
 *      Bumped at each successful raw cmp_hints_try_get_ex() pick
 *      where a CMP_HYP_BOUNDARY entry exists at the served
 *      (cmp_ip, width) AND the derive arm would not bail.
 *      Decoupled from the value-keyed would_pick / find_for_credit
 *      resolvers per the spec's Q3 analysis -- a counter that just
 *      counted "BOUNDARY won the precedence ladder" would stay
 *      structurally near zero (EXACT is populated at every
 *      observation and always outranks).  This is the headline
 *      shadow metric: it estimates how often the boundary arm
 *      WOULD have something to inject if precedence let it.
 *  cmp_hyp_boundary_credit_window_hits
 *      Bumped in cmp_hyp_find_for_credit()'s BOUNDARY arm each
 *      time a credited value resolves to BOUNDARY via the
 *      |v - exemplar| <= 2 window (EXACT / ENUM / BITMASK / RANGE
 *      having all missed first).  This is the conversion proof
 *      for the lane: a credited PC / transition win at a value
 *      nothing else explains is a boundary-adjacent neighbour the
 *      derive ladder produced.
 *
 * Kill criterion (same bar that killed exact-inject): if a
 * representative run shows cmp_hyp_live_injected_by_kind[BOUNDARY]
 * in the hundreds with cmp_hyp_pc_wins / cmp_hyp_transition_wins
 * credited to BOUNDARY ~= 0, the lane is dead -- strip it.
 */
unsigned long cmp_hyp_boundary_inserted;
unsigned long cmp_hyp_boundary_candidate_available;
unsigned long cmp_hyp_boundary_credit_window_hits;
};
