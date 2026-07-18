#ifndef _TRINITY_STATS_SUBSYS_PERF_CHAINS_H
#define _TRINITY_STATS_SUBSYS_PERF_CHAINS_H

struct perf_chains_stats {
	/* perf_event_chains childop counters */
	unsigned long runs;		/* total invocations */
	unsigned long groups_created;	/* group leader fd opened successfully */
	unsigned long ioctl_ops;	/* PERF_EVENT_IOC_* calls made */
};

#endif /* _TRINITY_STATS_SUBSYS_PERF_CHAINS_H */
