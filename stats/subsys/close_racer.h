#ifndef _TRINITY_STATS_SUBSYS_CLOSE_RACER_H
#define _TRINITY_STATS_SUBSYS_CLOSE_RACER_H

struct close_racer_stats {
	/* close_racer childop counters */
	unsigned long runs;			/* total close_racer invocations */
	unsigned long pairs;		/* cycles where close+join completed */
	unsigned long failed;		/* socketpair/pipe2 returned -1 */
	unsigned long thread_spawn_fail;	/* pthread_create returned non-zero */
};

#endif /* _TRINITY_STATS_SUBSYS_CLOSE_RACER_H */
