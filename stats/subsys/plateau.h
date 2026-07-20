#ifndef _TRINITY_STATS_SUBSYS_PLATEAU_H
#define _TRINITY_STATS_SUBSYS_PLATEAU_H

struct plateau_stats {
	/* Coverage-plateau detector transition counters, bumped from
	 * kcov_plateau_check() on the rising edge (healthy -> plateau, when
	 * the sliding-window edge-discovery rate falls below
	 * KCOV_PLATEAU_ENTER_THRESHOLD) and the falling edge (plateau ->
	 * healthy, when the rate recovers).  Distinct from the one-shot
	 * stats.log warning so a forensic / cron consumer can tell how many
	 * distinct plateau episodes a long fuzz hit without parsing the
	 * mirrored log.  Bumped from the parent-only tick path so the relaxed
	 * add-fetch is for ordering hygiene rather than concurrent writers. */
	unsigned long entered;
	unsigned long exited;

	/* bucket_seen[] integrity-canary counters, bumped from
	 * kcov_bitmap_canary_check() on the parent's periodic tick.
	 * kcov_collect() sets bucket_seen bits monotonically and bumps
	 * edges_found once per bit-flip, so popcount(bucket_seen) ==
	 * edges_found is a by-construction identity (see the comment on
	 * kcov_bitmap_recount).  A wild writer that scribbles bucket_seen
	 * mid-run silently breaks the identity until the next save path
	 * notices.  The canary samples and popcount-compares against an
	 * in-source deficit threshold (KCOV_BITMAP_CANARY_DEFICIT) chosen
	 * to clear realistic per-scan memory-ordering jitter while still
	 * catching the page-class scribbles operators have seen.  Stats:
	 *   bucket_canary_checks   - every successful sample, the
	 *                            denominator for the deficit rate.
	 *   bucket_canary_deficits - samples where (edges_before -
	 *                            popcount) exceeded the threshold,
	 *                            i.e. the alarm fired.  Non-zero
	 *                            means the wild-writer hypothesis
	 *                            has direct evidence in the current
	 *                            run; cross-reference the matching
	 *                            stats.log CANARY line for the
	 *                            deficit magnitude.
	 * Both fields are parent-only writers; the RELAXED add-fetch is
	 * for read-side ordering hygiene only. */
	unsigned long bucket_canary_checks;
	unsigned long bucket_canary_deficits;

	/* Mutation-attribution win/trial inversion canary, bumped from
	 * minicorpus_mut_attrib_canary_check() on the parent's periodic
	 * tick.  The win bump is lexically nested under the trial bump
	 * in minicorpus.c and gated on (found_new && baseline_established),
	 * so mut_wins[i] <= mut_trials[i] (and the structured equivalent)
	 * is a by-construction identity at every instant.  A stray writer
	 * scribbling a wins[] counter word silently inverts the ratio and
	 * misleads the bandit's per-op weighting until the next stats
	 * dump notices.  Bumped once per inverted op per scan; non-zero
	 * is evidence the wins/trials counter region took a hit in the
	 * current run, with the matching stats.log CANARY line carrying
	 * the witnessed op + counts.  Parent-only writer; the RELAXED
	 * add-fetch is for read-side ordering hygiene only. */
	unsigned long mut_attrib_inversion_caught;

	/* Number of windows the orchestrator above the strategy picker
	 * forced STRATEGY_RANDOM in response to plateau_active, i.e. windows
	 * with selection_reason == SR_PLATEAU_FORCE.  Excluded from the
	 * UCB learner's reward history; surfaced separately in
	 * dump_strategy_stats() so the operator can size the intervention
	 * cohort against the policy-chosen cohort.  Bumped by the CAS-winning
	 * child inside select_next_strategy(); relaxed because the rotation
	 * path already serialises via syscalls_at_last_switch CAS. */
	unsigned long forced_windows;
};

#endif /* _TRINITY_STATS_SUBSYS_PLATEAU_H */
