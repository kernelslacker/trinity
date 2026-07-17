#ifndef _TRINITY_STATS_SUBSYS_FLOCK_THRASH_H
#define _TRINITY_STATS_SUBSYS_FLOCK_THRASH_H

/* flock_thrash childop counters */
struct flock_thrash_stats {
	unsigned long runs;	/* total flock_thrash invocations */
	unsigned long locks;	/* successful flock() calls */
	unsigned long failed;	/* flock() returned -1 (EWOULDBLOCK/EINTR/...) */
};

#endif /* _TRINITY_STATS_SUBSYS_FLOCK_THRASH_H */
