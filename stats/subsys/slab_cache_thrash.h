#ifndef _TRINITY_STATS_SUBSYS_SLAB_CACHE_THRASH_H
#define _TRINITY_STATS_SUBSYS_SLAB_CACHE_THRASH_H

/* Cardinality of enum slab_target (private to the childop at
 * childops/misc/slab-cache-thrash.c).  Declared here so the runs[] array
 * below has a size and so the childop's own _Static_assert can keep
 * enum-tail parity without pulling the enum's public exposure. */
#define NR_SLAB_TARGETS 7

struct slab_cache_thrash_stats {
	/* slab_cache_thrash childop: per-target burst invocation count,
	 * indexed by enum slab_target. */
	unsigned long runs[NR_SLAB_TARGETS];
};

#endif /* _TRINITY_STATS_SUBSYS_SLAB_CACHE_THRASH_H */
