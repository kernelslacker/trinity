#ifndef _TRINITY_STATS_SUBSYS_FUTEX_STORM_H
#define _TRINITY_STATS_SUBSYS_FUTEX_STORM_H

/* futex_storm childop counters */
struct futex_storm_stats {
	unsigned long runs;		/* total futex_storm invocations */
	unsigned long inner_crashed;	/* inner worker died by signal */
	unsigned long iters;		/* cumulative inner-worker futex syscalls */
};

#endif /* _TRINITY_STATS_SUBSYS_FUTEX_STORM_H */
