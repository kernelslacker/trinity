#ifndef _TRINITY_STATS_SUBSYS_PIPE_THRASH_H
#define _TRINITY_STATS_SUBSYS_PIPE_THRASH_H

/* pipe_thrash childop counters */
struct pipe_thrash_stats {
	unsigned long runs;		/* total pipe_thrash invocations */
	unsigned long pipes;		/* successful pipe()/pipe2() calls */
	unsigned long socketpairs;	/* successful socketpair() calls */
	unsigned long alloc_failed;	/* create syscall returned -1 */
};

#endif /* _TRINITY_STATS_SUBSYS_PIPE_THRASH_H */
