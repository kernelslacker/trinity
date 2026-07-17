#ifndef _TRINITY_STATS_SUBSYS_MOUNT_CHURN_H
#define _TRINITY_STATS_SUBSYS_MOUNT_CHURN_H

/* mount_churn childop counters */
struct mount_churn_stats {
	unsigned long runs;	/* total mount_churn invocations */
	unsigned long mounts;	/* successful mount() in private ns */
	unsigned long umounts;	/* successful umount2() */
	unsigned long failed;	/* mkdir/mount/umount returned -1 */
};

#endif /* _TRINITY_STATS_SUBSYS_MOUNT_CHURN_H */
