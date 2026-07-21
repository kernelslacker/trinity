#ifndef _TRINITY_STATS_SUBSYS_PICKER_BANDIT_H
#define _TRINITY_STATS_SUBSYS_PICKER_BANDIT_H

#include "reach-band.h"		/* REACH_BAND_NR */
#include "syscall.h"		/* MAX_NR_SYSCALL */

/*
 * Scheduler picker / bandit observability -- CMP + edge-count
 * secondary reward-term firing rates, explorer vs bandit pool
 * per-syscall new-edge attribution, SHADOW-ONLY deep-but-warm
 * "warm reserve" candidate accounting (raw + plateau-intersected),
 * warm-plateau wall-lever eligibility + would-suppress projection,
 * and reach-banded silent-regime picker weight adjustment (per-band
 * classification + would-demote/would-boost dispositions).  See
 * include/reach-band.h for the band contract and include/cmp-hyp.h
 * for the deep-but-warm predicate.  The surrounding struct stats_s
 * composes an instance of struct picker_bandit_stats as its
 * "picker_bandit" member.
 */
struct picker_bandit_stats {
	/* Bandit secondary reward-term firing (CMP + edge-count).
	 * Bumped from the CAS-serialised maybe_rotate_strategy() /
	 * bandit_record_pull() path -- plain unsigned long with
	 * __atomic_fetch_add suffices. */
	unsigned long cmp_reward_added;
	unsigned long edge_count_reward_added;

	/* Explorer-pool pick attribution + per-pool new-edge discovery
	 * counters (CALL-COUNT semantics; a call uncovering 50 edges
	 * bumps by 1, same shape as pc_edge_calls_by_strategy[]). */
	unsigned long strategy_explorer_picks;
	unsigned long explorer_pool_edges_discovered;
	unsigned long bandit_pool_edges_discovered;

	/* Per-syscall new-edge attribution, split by strategy pool.
	 * Bumped from dispatch_step's new-edge branch with the real
	 * bucket-edge count returned by kcov_collect() -- per-call
	 * distinct-edge weight, not 1-per-call.  ~16 KiB total; surfaced
	 * via top_syscalls_periodic_dump() only. */
	unsigned long edges_per_syscall_bandit[MAX_NR_SYSCALL];
	unsigned long edges_per_syscall_explorer[MAX_NR_SYSCALL];

	/* SHADOW-ONLY deep-but-warm candidate accounting.  A call
	 * qualifies when post-collect signals show no new coverage
	 * (new_edges == 0 AND new_cmp == 0) yet the call still ran a
	 * meaningful amount of kernel code (per-call distinct_pcs
	 * outranks the syscall's lifetime mean, or per-call PC trace
	 * length approached raw truncation).  Two clauses OR'd -- the
	 * population a future capped-reserve experiment would retain
	 * for replay.  This commit only counts them. */
	unsigned long warm_reserve_candidates_total;
	unsigned long warm_reserve_candidates[MAX_NR_SYSCALL];

	/* SHADOW-ONLY would-replay-demand counters, paired with the
	 * warm_reserve_candidates* pair above.  Intersect the deep-but-
	 * warm predicate with the CMP_RISING_PC_FLAT plateau hypothesis
	 * (the window in which a STAGE B capped-reserve experiment would
	 * actually fire the replay) so the STAGE B build can size its
	 * ring + dispatch path against realised rates. */
	unsigned long warm_reserve_during_plateau_total;
	unsigned long warm_reserve_during_plateau[MAX_NR_SYSCALL];

	/* SHADOW-ONLY warm-plateau "wall lever" accounting.  Shadow
	 * gate that identifies high-call zero-yield syscalls during a
	 * warm-plateau window and projects the pick-budget those
	 * candidates would free if a live suppression variant were
	 * enabled.  See wall_lever_should_suppress_shadow() /
	 * wall_lever_refresh_baseline() in strategy.c -- eligibility
	 * set is recomputed at every plateau-active rotation so the
	 * gate adapts to the fleet's own per-syscall calls
	 * distribution rather than a static denylist.
	 *
	 *  eligible_total       : bump per pick where the shadow
	 *    predicate was evaluated (plateau_active + readable data).
	 *  would_suppress_total : bump per pick where the suppression
	 *    predicate fired -- projected pick share a live wall-lever
	 *    variant would reclaim.  Strictly <= eligible_total.
	 *  would_suppress[nr]   : per-syscall split. */
	unsigned long wall_lever_eligible_total;
	unsigned long wall_lever_would_suppress_total;
	unsigned long wall_lever_would_suppress[MAX_NR_SYSCALL];

	/* Shadow per-band counters for reach-banded silent-regime
	 * picker weight adjustment.  Bumped from the band classifi-
	 * cation gate in frontier_cold_weight() under SHADOW_ONLY or
	 * COMBINED; the REACH_BAND_OFF early-out keeps default-mode
	 * byte-identical.
	 *
	 *  picks_per_band[LOW/MID/HIGH] : per-band classification count.
	 *  would_demote_mid             : MID-band calls where the
	 *    staleness predicate fired and the band gate halved the
	 *    silent-regime weight.
	 *  would_boost_high             : HIGH-band calls where the
	 *    freshness predicate fired and the band gate lifted the
	 *    silent-regime weight. */
	unsigned long reach_band_picks_per_band[REACH_BAND_NR];
	unsigned long reach_band_would_demote_mid;
	unsigned long reach_band_would_boost_high;
};

#endif	/* _TRINITY_STATS_SUBSYS_PICKER_BANDIT_H */
