#ifndef _TRINITY_STATS_SUBSYS_MEMORY_PRESSURE_H
#define _TRINITY_STATS_SUBSYS_MEMORY_PRESSURE_H

/*
 * memory_pressure childop counters.  MADV_PAGEOUT + refault cycle
 * driver in childops/mm/memory-pressure.c bumps runs once per
 * completed invocation (RELAXED on shm->stats); diagnostic-only.
 *
 * Bespoke (non-category) RAW group.  The surrounding struct stats_s
 * composes an instance of struct memory_pressure_stats as its
 * "memory_pressure" member.
 */
struct memory_pressure_stats {
	unsigned long runs;	/* completed MADV_PAGEOUT + refault cycles */
};

#endif	/* _TRINITY_STATS_SUBSYS_MEMORY_PRESSURE_H */
