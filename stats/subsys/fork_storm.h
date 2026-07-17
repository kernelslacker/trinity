#ifndef _TRINITY_STATS_SUBSYS_FORK_STORM_H
#define _TRINITY_STATS_SUBSYS_FORK_STORM_H

/* fork_storm childop counters */
struct fork_storm_stats {
	unsigned long runs;		/* total fork_storm invocations */
	unsigned long forks;		/* grandchildren successfully forked */
	unsigned long failed;		/* fork() returned -1 (e.g. EAGAIN) */
	unsigned long nested;		/* depth-1 nested forks completed */
	unsigned long reaped_signal;	/* grandchildren reaped that died by signal */
};

#endif /* _TRINITY_STATS_SUBSYS_FORK_STORM_H */
