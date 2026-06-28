#pragma once

/* --reach-band: reach-banded adjustment for the silent-regime picker
 * weight returned by frontier_cold_weight() in random-syscall.c.
 *
 * A syscall is banded by its productive-call count -- per_syscall_
 * edges[nr] plus the warm-loaded per_syscall_edges_prior[nr], i.e.
 * the same "edges_total" basis the cold-skip and expensive-adaptive
 * helpers already use:
 *
 *   LOW    reach <  REACH_BAND_MID_THRESHOLD
 *   MID    REACH_BAND_MID_THRESHOLD <= reach < REACH_BAND_HIGH_THRESHOLD
 *   HIGH   reach >= REACH_BAND_HIGH_THRESHOLD
 *
 * The graduated cold-skip path in kcov_syscall_cold_skip_pct() treats
 * barren and stale uniformly regardless of how much reach a syscall
 * has accumulated.  The MID band -- 10..999 productive calls -- eats
 * most of the call budget, and within it a "once productive, now
 * stale" slot is far less worth re-running than a syscall that has
 * never produced an edge at all.  Conversely, a HIGH-reach syscall
 * still producing fresh edges is the long-tail discoverer the silent
 * regime should keep visiting even though its edges/calls ratio
 * sinks the cold-only weight to near zero.  The MID branch demotes
 * the stale slot harder than the cold curve alone; the HIGH branch
 * lifts the productive slot's weight back up.
 *
 *   OFF          - default.  The hook in frontier_cold_weight()
 *                  bypasses the band classification entirely: no
 *                  band edges_prior / last_edge_at / total_calls
 *                  load, no arithmetic, no weight change.  Fixed-
 *                  seed dry-run is byte-identical to a build before
 *                  the row -- the mode-load itself consumes no RNG.
 *   SHADOW_ONLY  - compute the band classification and the would-
 *                  demote / would-boost decision, but the live
 *                  returned weight stays at the pre-hook value.
 *                  Picks identical to OFF for a given seed.
 *                  Placeholder for a follow-up that adds per-band
 *                  shadow counters in stats.c.
 *   COMBINED     - the band adjustment is applied to the weight
 *                  the silent-regime accept gate draws against.
 *                  Only mode that diverges from OFF.
 *
 * Degrade-safe: when kcov_shm is unavailable or nr is out of range
 * frontier_cold_weight() short-circuits before the band hook is
 * reached, matching the FRONTIER_COLD_SCALE fallback the rest of
 * the picker file already takes.  Reads from per_syscall_edges_
 * prior / total_calls / last_edge_at are __ATOMIC_RELAXED -- a
 * load tear that observes last > total or reach below the live
 * band degrades the hook to "no band action" rather than wrapping
 * an unsigned subtract, mirroring the guard idiom frontier_cold_
 * weight already uses for its edges >= calls case.
 */
enum reach_band_mode {
	REACH_BAND_OFF = 0,
	REACH_BAND_SHADOW_ONLY = 1,
	REACH_BAND_COMBINED = 2,
};

extern enum reach_band_mode reach_band_mode;

/* Band index for the shadow per-band pick counters in
 * shm->stats.reach_band_picks_per_band[].  Order matches the
 * classification chain in frontier_cold_weight() -- LOW is the
 * fall-through (reach < MID_THRESHOLD), MID is
 * [MID_THRESHOLD, HIGH_THRESHOLD), HIGH is >= HIGH_THRESHOLD. */
enum reach_band_idx {
	REACH_BAND_IDX_LOW = 0,
	REACH_BAND_IDX_MID = 1,
	REACH_BAND_IDX_HIGH = 2,
	REACH_BAND_NR = 3,
};

/* Band boundaries on edges_total (per_syscall_edges + _prior).  10
 * marks the floor above which the graduated cold-skip path has
 * already had a fair shot at filtering the slot via its KCOV_COLD_
 * THRESHOLD gap window; 1000 is the deep-reach floor where a
 * syscall has earned the silent-regime protection bump regardless
 * of edges/calls ratio. */
#define REACH_BAND_MID_THRESHOLD	10UL
#define REACH_BAND_HIGH_THRESHOLD	1000UL

/* MID-band stale demote: halve the silent-regime weight.  Matches
 * the magnitude of the cold-skip path's 50% baseline at the first
 * KCOV_COLD_THRESHOLD-sized gap step -- one full cold-skip baseline
 * worth of additional demote layered on top, harder than the flat
 * graduated curve gives a stale MID slot today. */
#define REACH_BAND_MID_STALE_DEMOTE_DEN	2UL

/* HIGH-band fresh boost: add a quarter of the remaining headroom to
 * FRONTIER_COLD_SCALE back onto the weight.  Keeps the boost a
 * fraction of the cap so a syscall whose cold-only weight is
 * already near FRONTIER_COLD_SCALE moves at most a few steps,
 * while a low cold-weight HIGH-reach slot (the long-tail
 * discoverer whose edges/calls ratio sinks it to ~0) earns the
 * largest absolute lift. */
#define REACH_BAND_HIGH_FRESH_BOOST_DEN	4UL
