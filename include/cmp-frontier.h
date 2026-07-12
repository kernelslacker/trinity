#pragma once

/* --cmp-frontier: CMP-weighted alternate picker arm for the silent
 * regime of set_syscall_nr_coverage_frontier() in random-syscall.c.
 *
 * Design rationale: Documentation/cmp-frontier.md
 *
 * Mode ladder (each rung layers more of the pipeline on the prior):
 *   OFF          - default; arm bypassed, no RNG / CMP-counter load,
 *                  byte-identical to a pre-row build under fixed seed.
 *   SHADOW_ONLY  - compute alt weight + would-route decision, bump
 *                  shadow counters; live picks identical to OFF.
 *   COMBINED     - on PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT picks,
 *                  replace the PC-led weight with the CMP-weighted
 *                  alternate; off-plateau picks retain PC-led.  Only
 *                  mode that diverges from OFF.
 *
 * Degrade-safe: kcov_shm == NULL or nr >= MAX_NR_SYSCALL bails to
 * zero weight before any CMP counter is touched; a torn plateau-
 * hypothesis load degrades the COMBINED arm to "no route" for that
 * pick.
 */
enum cmp_frontier_mode {
	CMP_FRONTIER_OFF = 0,
	CMP_FRONTIER_SHADOW_ONLY = 1,
	CMP_FRONTIER_COMBINED = 2,
};

extern enum cmp_frontier_mode cmp_frontier_mode;

/* Scale on the ilog2-clamped CMP-signal sum; saturated at
 * FRONTIER_COLD_SCALE in the helper.  The signal sum is
 * ilog2(per_syscall_cmp_inserts + 1) + ilog2(childop_cmp_pool_inserts
 * + 1) plus a conversion-rate bonus derived from
 * per_syscall_cmp_injected vs (per_syscall_cmp_hint_pc_wins +
 * per_syscall_cmp_hint_transition_wins) -- gated on
 * CMP_FRONTIER_MIN_INJECTED so a 1/1 noise spike cannot dominate,
 * capped by CMP_FRONTIER_CONVERSION_SCALE to the same magnitude
 * band as the inserts side, and degrading to inserts-only for
 * 0%-converters.  Derivation of the 8x factor and the conversion
 * bonus lives in Documentation/cmp-frontier.md. */
#define CMP_FRONTIER_SIGNAL_SCALE	8UL
