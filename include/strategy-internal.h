#pragma once

/*
 * strategy-internal.h -- shared private declarations across the
 * strategy.c family of translation units.
 *
 * Symbols here are NOT part of the public strategy API in
 * include/strategy.h.  They are only declared here because they
 * cross a strategy-* TU boundary after the per-concern split of
 * the old monolithic strategy.c.  Do not include from anywhere
 * outside strategy.c / strategy-*.c.
 */

/*
 * Random-rescue amplification thresholds.  A class must clear an
 * absolute floor (so a handful of stray rescues do not whip the
 * orchestrator around between arms) AND a 2x lead over the second-best
 * class (so two near-tied classes default back to plain RANDOM rather
 * than coin-flipping the intervention).  Both numbers are conservative
 * -- the amplification is a temporary modifier on a single intervention
 * window, easy to recover from on the next rotation if the dominant
 * class shifts.
 *
 * Defined here because dominant_rescue_class() (strategy.c) and
 * dump_strategy_stats_rescue_classes() (strategy-stats-dump.c) both
 * read these thresholds and must agree on the values.
 */
#define RRC_AMPLIFY_MIN_COUNT  32UL
#define RRC_AMPLIFY_LEAD_RATIO 2UL
