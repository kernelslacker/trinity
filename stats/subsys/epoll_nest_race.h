#ifndef _TRINITY_STATS_SUBSYS_EPOLL_NEST_RACE_H
#define _TRINITY_STATS_SUBSYS_EPOLL_NEST_RACE_H

/* epoll_nest_race childop counters */
struct epoll_nest_race_stats {
	unsigned long runs;		/* total epoll_nest_race invocations */
	unsigned long ctl_calls;	/* epoll_ctl calls issued (ADD of epfd targets) */
	unsigned long racer_laps;	/* close/open racer thread iterations completed */
	unsigned long failed;		/* epoll_ctl ADD returned -1 (non-EEXIST/-EINVAL) */
};

#endif /* _TRINITY_STATS_SUBSYS_EPOLL_NEST_RACE_H */
