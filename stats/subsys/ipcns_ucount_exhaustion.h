#ifndef _TRINITY_STATS_SUBSYS_IPCNS_UCOUNT_EXHAUSTION_H
#define _TRINITY_STATS_SUBSYS_IPCNS_UCOUNT_EXHAUSTION_H

struct ipcns_ucount_exhaustion_stats {
	/* Total ipcns_ucount_exhaustion invocations that completed all lanes. */
	unsigned long runs;
	/* Inner child died by signal (unexpected crash inside userns). */
	unsigned long inner_crashed;
};

#endif /* _TRINITY_STATS_SUBSYS_IPCNS_UCOUNT_EXHAUSTION_H */
