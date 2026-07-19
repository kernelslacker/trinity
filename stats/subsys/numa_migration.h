#ifndef _TRINITY_STATS_SUBSYS_NUMA_MIGRATION_H
#define _TRINITY_STATS_SUBSYS_NUMA_MIGRATION_H

struct numa_migration_stats {
	/* numa_migration_churn childop counters */
	unsigned long runs;			/* total numa_migration_churn invocations */
	unsigned long calls;			/* total mbind/migrate/move/set_mempolicy calls issued */
	unsigned long failed;			/* migration syscall returned -1 */
	unsigned long no_numa;			/* attempted invocations skipped (single-node host) */
	unsigned long sysfs_unreadable;		/* /sys/devices/system/node/online open/read failed */
};

#endif /* _TRINITY_STATS_SUBSYS_NUMA_MIGRATION_H */
