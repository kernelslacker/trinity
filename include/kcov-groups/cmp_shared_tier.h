#pragma once

/* Sub-struct of struct kcov_shared, embedded as .cmp_shared_tier.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_cmp_shared_tier {
unsigned long cmp_shared_tier_ips;
unsigned long cmp_shared_tier_entries;
unsigned long cmp_shared_tier_entry_path_excluded_ips;
unsigned long cmp_shared_tier_shadow_warmstart_eligible;
unsigned long cmp_shared_tier_shadow_dedup_supplied;

/*
 * COMBINED-mode QUARANTINED serve counters for the shared
 * cmp_ip tier -- the credit-partitioned live wire-up of the
 * shadow eligibility rate above.  Fire only when
 * cmp_shared_tier_mode == CMP_SHARED_TIER_MODE_COMBINED;
 * SHADOW_ONLY and OFF leave all four at zero and a fixed-seed
 * pick stream stays bit-for-bit identical to the pre-serve
 * baseline.
 *
 *  cmp_shared_tier_serves
 *      Bumped once per cmp_shared_tier_try_serve_cold_miss()
 *      return that actually served a value to the get-path
 *      (dice passed, non-excluded bucket elected, transform
 *      applied, accept range not violated).  Ratio against
 *      cmp_shared_tier_shadow_warmstart_eligible is the serve
 *      fraction of the opportunity rate the shadow probe
 *      already measures -- capped at 1/CMP_SHARED_TIER_SERVE_
 *      DICE by the per-eligible-miss dice.
 *  cmp_shared_tier_serve_accept_reject
 *      Bumped once per served value the caller's accept range
 *      subsequently rejected (dice + bucket election passed,
 *      but the shared-tier value fell outside [lo, hi]).  The
 *      invalid-rate half of the "what fraction of shared-
 *      served values yield progress OR induce an out-of-range
 *      draw" question this lane is being measured on.
 *      Mirrors the CMP_HYP_LIVE_INJECT_REASON_ACCEPT_REJECT
 *      discipline the typed inject arm uses.
 *  cmp_hint_tier_shared_wins
 *  cmp_hint_tier_shared_misses
 *      Per-stash-entry PC outcome partition for shared-served
 *      entries, drained from cmp_hints_feedback_credit_pc().
 *      This is the ONLY credit lane a stash entry stamped
 *      served_from_shared reaches -- the drain skips the
 *      cmp_hint_credit_entry_per_syscall / _field per-entry
 *      bump, the cmp_hint_pc_wins_by_pool / _misses_by_pool
 *      partition, the cmp_hint_callsite_pc_wins / _misses
 *      partition, the cmp_hint_pool_zero_win_would_save /
 *      _retire zero-win-budget census, the
 *      cmp_hint_tier_recent / _durable / _durable_age wins /
 *      misses splits, and the typed-hyp cmp_hyp_credit_
 *      outcome / cmp_hyp_credit_consume / cmp_hyp_would_pick
 *      taps for every shared-served entry.  This is the load-
 *      bearing quarantine invariant: a cross-syscall shared-
 *      served value cannot masquerade as native durable /
 *      recent evidence in any operator-facing conversion rate
 *      or per-entry weight.  cmp_hint_tier_shared_wins /
 *      (cmp_hint_tier_shared_wins + cmp_hint_tier_shared_
 *      misses) is the shared-tier bootstrap's conversion rate;
 *      the go-live decision (promote shared-served constants
 *      into native pool evidence, or drop the serve path) is
 *      gated on this ratio + the accept-reject rate above,
 *      and lands in a follow-up commit off this measurement.
 *
 * Append-only at the tail per the existing convention so
 * consumer offsets stay stable.
 */
unsigned long cmp_shared_tier_serves;
unsigned long cmp_shared_tier_serve_accept_reject;
unsigned long cmp_hint_tier_shared_wins;
unsigned long cmp_hint_tier_shared_misses;
};
