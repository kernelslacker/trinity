#ifndef _TRINITY_STATS_SUBSYS_SCHED_CYCLER_H
#define _TRINITY_STATS_SUBSYS_SCHED_CYCLER_H

struct sched_cycler_stats {
	/* sched_cycler childop counters */
	unsigned long runs;	/* total sched_cycler invocations */
	unsigned long eperm;	/* sched_setattr denied (no CAP_SYS_NICE) */
};

#endif /* _TRINITY_STATS_SUBSYS_SCHED_CYCLER_H */
