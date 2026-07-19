#ifndef _TRINITY_STATS_SUBSYS_FDSTRESS_H
#define _TRINITY_STATS_SUBSYS_FDSTRESS_H

struct fdstress_stats {
	/* fd_stress childop counters, one per stress mode */
	unsigned long close_reopen;
	unsigned long dup2_replace;
	unsigned long type_confusion;
	unsigned long cloexec_toggle;
};

#endif /* _TRINITY_STATS_SUBSYS_FDSTRESS_H */
