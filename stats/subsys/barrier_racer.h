#ifndef _TRINITY_STATS_SUBSYS_BARRIER_RACER_H
#define _TRINITY_STATS_SUBSYS_BARRIER_RACER_H

/* barrier_racer childop counters */
struct barrier_racer_stats {
	unsigned long runs;		/* total barrier_racer invocations */
	unsigned long inner_crashed;	/* inner worker died by signal */
};

#endif /* _TRINITY_STATS_SUBSYS_BARRIER_RACER_H */
