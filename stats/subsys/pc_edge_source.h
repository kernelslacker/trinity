#ifndef _TRINITY_STATS_SUBSYS_PC_EDGE_SOURCE_H
#define _TRINITY_STATS_SUBSYS_PC_EDGE_SOURCE_H

#include "syscall.h"	/* MAX_NR_SYSCALL */

struct pc_edge_source_stats {
	/* RedQueen -> PC-edge conversion attribution, per-syscall.
	 *
	 * rq_saves[nr]
	 *     Bumped from minicorpus_save_with_reason() each time a corpus
	 *     entry is admitted to syscall nr's ring with the rq_sourced
	 *     provenance tag set (i.e. the saving child's in_reexec was true
	 *     -- the args came from a redqueen_reexec_step harvest).
	 *
	 * rq_pcedge_wins[nr]
	 *     Bumped from frontier_record_new_edge() (strategy.c) when the
	 *     call that produced the new PC bucket-edge for nr was a replay
	 *     of a corpus entry whose rq_sourced flag was set -- i.e. a
	 *     downstream PC win from a RedQueen-sourced save.
	 *
	 * The pair answers the harvest->edge bottleneck question: do the
	 * args RedQueen re-exec harvests actually convert to new PC edges
	 * once they're replayed?  Surfaced only via top_syscalls_periodic_
	 * dump() (alongside the existing per-pool per-syscall arrays) so
	 * the operator gets a per-window view of which syscalls have the
	 * highest RedQueen-sourced save rate vs which produce the highest
	 * downstream PC-edge wins.  Observability only -- no selection /
	 * reward / injection path consumes either array.  RELAXED add-fetch:
	 * cumulative diagnostic, window deltas come from the dump's
	 * snapshot+diff against the previous tick. */
	unsigned long rq_saves[MAX_NR_SYSCALL];
	unsigned long rq_pcedge_wins[MAX_NR_SYSCALL];

	/* Per-syscall errno-sourced provenance attribution.  The
	 * errno-gradient-save SHADOW/LIVE trigger scalars live in
	 * struct errno_gradient_stats (stats/subsys/errno_gradient.h) as
	 * save_would_save / save_did_save; the two per-syscall arrays
	 * below carry the same errno-source provenance one level down.
	 *
	 * errno_saves[nr]
	 *     Bumped from minicorpus_save_with_reason() each time an entry
	 *     is admitted to syscall nr's ring with the errno_sourced
	 *     provenance tag set (CORPUS_SAVE_REASON_ERRNO).  Mirror of
	 *     rq_saves[].
	 *
	 * errno_pcedge_wins[nr]
	 *     Bumped from frontier_record_new_edge() (strategy.c) when the
	 *     call that produced the new PC bucket-edge for nr was a replay
	 *     of a corpus entry whose errno_sourced flag was set -- the
	 *     errno-source conversion-rate counter.  Mirror of
	 *     rq_pcedge_wins[].
	 *
	 * Observability only -- no selection / reward / injection path
	 * consumes either.  RELAXED add-fetch matches the surrounding
	 * accounting.  Both start at zero on parent boot; warm-start does
	 * not persist stats counters. */
	unsigned long errno_saves[MAX_NR_SYSCALL];
	unsigned long errno_pcedge_wins[MAX_NR_SYSCALL];
};

#endif /* _TRINITY_STATS_SUBSYS_PC_EDGE_SOURCE_H */
