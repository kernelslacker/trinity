#ifndef _TRINITY_STATS_SUBSYS_MAP_SHARED_STRESS_H
#define _TRINITY_STATS_SUBSYS_MAP_SHARED_STRESS_H

struct map_shared_stress_stats {
	/* map_shared_stress childop counters */
	unsigned long runs;			/* total map_shared_stress invocations (pre-latch) */
	unsigned long setup_failed;		/* backing file create/ftruncate/mmap probe failed */
	unsigned long writeback_ok;		/* concurrent-writeback sub-op completed a burst */
	unsigned long dontfork_ok;		/* MADV_DONTFORK + fork COW-vs-shared sub-op completed a burst */
	unsigned long append_ok;		/* MAP_SHARED vs O_APPEND ordering sub-op completed a burst */
};

#endif /* _TRINITY_STATS_SUBSYS_MAP_SHARED_STRESS_H */
