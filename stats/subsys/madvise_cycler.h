#ifndef _TRINITY_STATS_SUBSYS_MADVISE_CYCLER_H
#define _TRINITY_STATS_SUBSYS_MADVISE_CYCLER_H

/* madvise_cycler childop counters */
struct madvise_cycler_stats {
	unsigned long runs;	/* total madvise_cycler invocations */
	unsigned long calls;	/* total madvise() calls issued */
	unsigned long failed;	/* madvise() returned -1 */
};

#endif /* _TRINITY_STATS_SUBSYS_MADVISE_CYCLER_H */
