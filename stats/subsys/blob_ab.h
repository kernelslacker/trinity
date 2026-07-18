#ifndef _TRINITY_STATS_SUBSYS_BLOB_AB_H
#define _TRINITY_STATS_SUBSYS_BLOB_AB_H

/*
 * --blob-ab-mode within-run A/B harness (default off, opt-in only):
 * four counters split by the mode the per-fill coin-flip picked (HAVOC
 * vs CMPDICT).  Bumped ONLY under --blob-ab-mode at the dispatch-site
 * novelty gate (the same site cmp_hints_feedback_credit_pc(new_edges)
 * fires from) -- fills is one credit per call that had a blob_fill(),
 * new_edges is that call's PC-edge novelty count.  The verdict metric
 * is new_edges / fills per mode across a long run; both arms share the
 * same warm corpus / kcov state at every moment so the per-fill rate is
 * the clean per-mode comparison.  Multiple blob_fills per call resolve
 * to latest-fill wins (rare on the ARG_BUF_SIZED surface).  When
 * --blob-ab-mode is absent all eight stay at zero and the dedicated
 * blob_ab_mode stat_category is suppressed by its gate.
 *
 * Distinct from struct blob_stats in stats/subsys/blob.h: those counters
 * observe the content-authoring lane itself (every non-OFF blob_fill()
 * bumps them), while these split a subset of dispatch-site outcomes by
 * which arm the coin-flip landed on.
 */
struct blob_ab_stats {
	unsigned long havoc_fills;
	unsigned long havoc_new_edges;
	unsigned long havoc_hit_cmp;
	unsigned long havoc_sum_cmp;
	unsigned long cmpdict_fills;
	unsigned long cmpdict_new_edges;
	unsigned long cmpdict_hit_cmp;
	unsigned long cmpdict_sum_cmp;
};

#endif /* _TRINITY_STATS_SUBSYS_BLOB_AB_H */
