#ifndef _TRINITY_STATS_SUBSYS_SIGNAL_STORM_H
#define _TRINITY_STATS_SUBSYS_SIGNAL_STORM_H

/* signal_storm childop counters */
struct signal_storm_stats {
	unsigned long runs;		/* total signal_storm invocations */
	unsigned long kill;		/* kill() calls issued (sig != 0) */
	unsigned long probe;		/* kill(pid, 0) existence probes */
	unsigned long sigqueue;		/* sigqueue() calls issued */
	unsigned long no_targets;	/* no live siblings to signal */
};

#endif /* _TRINITY_STATS_SUBSYS_SIGNAL_STORM_H */
