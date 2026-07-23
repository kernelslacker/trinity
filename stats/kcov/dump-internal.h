#ifndef _TRINITY_STATS_KCOV_DUMP_INTERNAL_H
#define _TRINITY_STATS_KCOV_DUMP_INTERNAL_H

/* Cross-file declarations for the stats/kcov/dump-*.c render family.
 * dump.c orders the per-domain renderers; each dump-<domain>.c holds
 * the corresponding block of definitions.  Output is byte-for-byte
 * identical to the pre-split single-file layout; see the split notes
 * in ~/rag/plans/shrink-plan-master.md ("stats/kcov/dump.c"). */

/* dump-base.c */
void dump_stats_render_kcov_base_stats(void);
void dump_stats_render_kcov_warm_known_hits(void);
void dump_stats_render_kcov_exit_edge_delta(void);
void dump_stats_render_kcov_exit_edge_totals(void);

/* dump-shadow.c (definition still in dump.c until the shadow split;
 * declared here so dump-base.c's base_stats can forward-call it). */
void dump_stats_render_kcov_shadow_measurements(void);

#endif	/* _TRINITY_STATS_KCOV_DUMP_INTERNAL_H */
