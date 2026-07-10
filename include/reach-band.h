#pragma once

/* --reach-band: reach-banded adjustment for the silent-regime picker
 * weight returned by frontier_cold_weight() in random-syscall.c.
 *
 * Design rationale: Documentation/reach-band.md
 *
 * Bands (edges_total = per_syscall_edges + _prior):
 *   LOW    reach <  REACH_BAND_MID_THRESHOLD
 *   MID    REACH_BAND_MID_THRESHOLD <= reach < REACH_BAND_HIGH_THRESHOLD
 *   HIGH   reach >= REACH_BAND_HIGH_THRESHOLD
 *
 * Mode ladder:
 *   OFF          - default; hook bypassed, no band load, no arithmetic.
 *                  Byte-identical to a pre-row build under fixed seed.
 *   SHADOW_ONLY  - compute would-demote / would-boost; live weight
 *                  unchanged.  Picks identical to OFF.
 *   COMBINED     - band adjustment applied to the silent-regime weight.
 *                  Only mode that diverges from OFF.
 *
 * Degrade-safe: kcov_shm unavailable or nr out of range short-circuits
 * upstream; RELAXED reads that observe last > total or reach below
 * band degrade to "no band action" rather than wrapping.
 */
enum reach_band_mode {
	REACH_BAND_OFF = 0,
	REACH_BAND_SHADOW_ONLY = 1,
	REACH_BAND_COMBINED = 2,
};

extern enum reach_band_mode reach_band_mode;

/* Band index for the shadow per-band pick counters in
 * shm->stats.reach_band_picks_per_band[].  Order matches the
 * classification chain in frontier_cold_weight(). */
enum reach_band_idx {
	REACH_BAND_IDX_LOW = 0,
	REACH_BAND_IDX_MID = 1,
	REACH_BAND_IDX_HIGH = 2,
	REACH_BAND_NR = 3,
};

/* Band boundaries on edges_total.  Sizing rationale in
 * Documentation/reach-band.md. */
#define REACH_BAND_MID_THRESHOLD	10UL
#define REACH_BAND_HIGH_THRESHOLD	1000UL

/* MID-band stale demote: halve the silent-regime weight. */
#define REACH_BAND_MID_STALE_DEMOTE_DEN	2UL

/* HIGH-band fresh boost: add a quarter of the remaining headroom to
 * FRONTIER_COLD_SCALE back onto the weight. */
#define REACH_BAND_HIGH_FRESH_BOOST_DEN	4UL
