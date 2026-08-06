#ifndef _TRINITY_STATS_SUBSYS_PROCESS_MRELEASE_RACE_H
#define _TRINITY_STATS_SUBSYS_PROCESS_MRELEASE_RACE_H

struct process_mrelease_race_stats {
	/* process_mrelease_race childop counters */
	unsigned long runs;		/* total invocations */
	unsigned long kill_rounds;	/* SIGKILL+race rounds completed */
	unsigned long success;		/* process_mrelease returned 0 (mm teardown hit) */
	unsigned long esrch;		/* process_mrelease returned ESRCH */
	unsigned long einval;		/* process_mrelease returned EINVAL */
	unsigned long eintr;		/* process_mrelease returned EINTR */
	unsigned long other_fail;	/* other errors from process_mrelease */
	unsigned long reap_slow;	/* victim reap exceeded poll timeout */
};

#endif /* _TRINITY_STATS_SUBSYS_PROCESS_MRELEASE_RACE_H */
