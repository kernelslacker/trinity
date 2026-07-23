#ifndef _TRINITY_STATS_KCOV_DUMP_INTERNAL_H
#define _TRINITY_STATS_KCOV_DUMP_INTERNAL_H

/* Cross-file declarations for the stats/kcov/dump-*.c render family.
 * dump.c orders the per-domain renderers; each dump-<domain>.c holds
 * the corresponding block of definitions.  Output is byte-for-byte
 * identical to the pre-split single-file layout; see the split notes
 * in ~/rag/plans/shrink-plan-master.md ("stats/kcov/dump.c"). */

#include "syscall.h"

/* dump-base.c */
void dump_stats_render_kcov_base_stats(void);
void dump_stats_render_kcov_warm_known_hits(void);
void dump_stats_render_kcov_exit_edge_delta(void);
void dump_stats_render_kcov_exit_edge_totals(void);

/* dump-topn.c */
void dump_stats_render_kcov_top_edges_and_cold(unsigned int nr_syscalls_to_scan, const struct syscalltable *table);
void dump_stats_render_kcov_per_syscall_yield_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table);
void dump_stats_render_kcov_per_syscall_dedup_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table);

/* dump-remote.c */
void dump_stats_render_kcov_remote_edge_producers(unsigned int nr_syscalls_to_scan, const struct syscalltable *table);
void dump_stats_render_kcov_per_syscall_last_edge_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table);
void dump_stats_render_kcov_per_syscall_last_efault_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table);
void dump_stats_render_kcov_per_syscall_local_pc_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table);

/* dump-reexec.c */
void dump_stats_render_kcov_cmp_hint_tier(void);
void dump_stats_render_kcov_reexec(void);
void dump_stats_render_kcov_ring_replay(void);
void dump_stats_render_kcov_cmp_field_consumer(void);

/* dump-shadow.c */
void dump_stats_render_kcov_shadow_measurements(void);
void dump_stats_render_kcov_kcov_probe_costs(void);
void dump_stats_render_kcov_kcov_dispatch_stats(void);

#endif	/* _TRINITY_STATS_KCOV_DUMP_INTERNAL_H */
