#pragma once

/* Sub-struct of struct kcov_shared, embedded as .reexec_flat.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_reexec_flat {
unsigned long reexec_attempts;
/*
 * Discrete count of re-exec attempts that produced
 * inner_new_cmp > 0.  Sibling of reexec_attempts (denominator)
 * and reexec_new_cmps_total (the SUM of inner_new_cmp across
 * winning attempts).  Bumped from redqueen_reexec_step() inside
 * the existing inner_new_cmp > 0 success block, once per winning
 * attempt.  Lets a Phase-0 funnel read pair the two ratios:
 *   - hit-rate           = reexec_attempts_with_new_cmp / reexec_attempts
 *   - mean novelty/win   = reexec_new_cmps_total / reexec_attempts_with_new_cmp
 * the existing pair (sum / attempts) conflates them.
 */
unsigned long reexec_attempts_with_new_cmp;
unsigned long reexec_attribution_found;
unsigned long reexec_attribution_ambiguous;
unsigned long reexec_attribution_width_match;
unsigned long reexec_new_cmps_total;
unsigned long reexec_skipped_destructive;
unsigned long reexec_skipped_validate_silent;
unsigned long reexec_window_cap_hit;

/* Per-syscall new_cmp total attributed to re-exec dispatches.
 * Sibling of per_syscall_cmp_inserts for the re-exec lift signal:
 * lift_ratio_per_syscall = reexec_per_call_new_cmps /
 *                          baseline_per_call_new_cmps
 * is the per-syscall version of the run-wide primary lift metric:
 * new CMP novelty per call gained from re-exec over baseline. */
unsigned long per_syscall_cmp_novelty_reexec[MAX_NR_SYSCALL];
};
