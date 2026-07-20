#ifndef _TRINITY_STATS_SUBSYS_TRANSITION_EDGE_H
#define _TRINITY_STATS_SUBSYS_TRANSITION_EDGE_H

#include "strategy.h"	/* NR_STRATEGIES */

struct transition_edge_stats {
	/* Per-strategy transition-reward attribution.  Parallel in shape to
	 * shm->pc_edge_calls_by_strategy[] / shm->pc_edge_count_by_strategy[]
	 * (which live in shm_s, not here -- the strategy-indexed pair was
	 * the established home before stats.h gained transition fields) but
	 * carrying the transition-coverage signal instead of the PC-edge
	 * signal.  Bumped from random-syscall.c at the kcov_collect call
	 * site using child->strategy_at_pick when transitions_this_call > 0.
	 *
	 * calls_by_strategy[strat]
	 *     Bumps by 1 per kcov_collect() call that flipped >=1 new
	 *     transition slot (matching the per_syscall_transition_edges
	 *     call-count semantics).  Window delta against
	 *     calls_at_window_start gives the per-strategy "how many calls
	 *     under this arm produced a transition this window" — symmetric
	 *     to the PC-edge call-count rotation reads.
	 *
	 * count_by_strategy[strat]
	 *     Bumps by min(transitions_this_call, TRANSITION_PER_CALL_
	 *     REWARD_CAP) per kcov_collect() call (raw real-flip count,
	 *     capped per-call to keep one pathological trace from
	 *     monopolizing the per-strategy delta).  See the
	 *     TRANSITION_PER_CALL_REWARD_CAP comment in include/kcov.h for
	 *     the cap rationale; the uncapped per_syscall_transition_edges_
	 *     real array stays the stats-dump observability signal.  The
	 *     per-strategy window delta is what bandit_record_pull() reads
	 *     and folds into the bandit reward total under COMBINED.
	 *
	 * count_at_window_start
	 *     Single-slot snapshot of count_by_strategy[next] reseeded at
	 *     every rotation in maybe_rotate_strategy(), matching the
	 *     existing pc_edge_count_at_window_start / bandit_cmp_at_
	 *     window_start cadence.  Read at the top of bandit_record_pull
	 *     to compute the per-window transition delta the COMBINED-mode
	 *     reward folds in.  Lives here (not in shm_s) — semantically
	 *     equivalent to the shm-side window-start snapshots since the
	 *     rotation handler is the single writer.
	 *
	 * calls_at_window_start
	 *     Companion snapshot for the calls-by-strategy counter.  Same
	 *     reseed cadence; consumers that want a "productive call rate"
	 *     numerator (per-strategy calls-with-transitions / total calls)
	 *     read this snapshot the same way the bandit reads the count
	 *     snapshot. */
	unsigned long calls_by_strategy[NR_STRATEGIES];
	unsigned long count_by_strategy[NR_STRATEGIES];
	unsigned long count_at_window_start;
	unsigned long calls_at_window_start;
};

#endif /* _TRINITY_STATS_SUBSYS_TRANSITION_EDGE_H */
