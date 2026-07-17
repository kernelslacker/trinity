#ifndef _TRINITY_STATS_SUBSYS_EPOLL_VOLATILITY_H
#define _TRINITY_STATS_SUBSYS_EPOLL_VOLATILITY_H

/* epoll_volatility childop counters */
struct epoll_volatility_stats {
	unsigned long runs;		/* total epoll_volatility invocations */
	unsigned long ctl_calls;	/* total epoll_ctl ADD/MOD/DEL calls (success + fail) */
	unsigned long failed;		/* epoll_ctl returned -1 (EEXIST/ENOENT/EINVAL/...) */
};

#endif /* _TRINITY_STATS_SUBSYS_EPOLL_VOLATILITY_H */
