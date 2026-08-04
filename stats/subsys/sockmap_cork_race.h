#ifndef _TRINITY_STATS_SUBSYS_SOCKMAP_CORK_RACE_H
#define _TRINITY_STATS_SUBSYS_SOCKMAP_CORK_RACE_H

struct sockmap_cork_race_stats {
	/* sockmap_cork_race childop counters */
	unsigned long runs;		/* total invocations */
	unsigned long setup_failed;	/* TCP loopback pair setup failed */
	unsigned long map_failed;	/* BPF_MAP_CREATE(SOCKMAP) failed */
	unsigned long prog_failed;	/* BPF_PROG_LOAD(SK_MSG) failed */
	unsigned long attach_failed;	/* BPF_PROG_ATTACH(SK_MSG_VERDICT) failed */
	unsigned long enroll_failed;	/* BPF_MAP_UPDATE_ELEM (sock enroll) failed */
	unsigned long races_run;	/* concurrent sender bursts completed */
};

#endif /* _TRINITY_STATS_SUBSYS_SOCKMAP_CORK_RACE_H */
