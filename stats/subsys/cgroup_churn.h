#ifndef _TRINITY_STATS_SUBSYS_CGROUP_CHURN_H
#define _TRINITY_STATS_SUBSYS_CGROUP_CHURN_H

struct cgroup_churn_stats {
	/* cgroup_churn childop counters */
	unsigned long runs;			/* total cgroup_churn invocations */
	unsigned long mkdirs;			/* successful mkdir() under /sys/fs/cgroup/ */
	unsigned long rmdirs;			/* successful rmdir() under /sys/fs/cgroup/ */
	unsigned long failed;			/* mkdir or rmdir returned -1 */
	unsigned long psi_race_runs;		/* PSI pressure_write race sub-mode entries */
	unsigned long psi_race_writes;		/* successful pressure-file write() inside race */
	unsigned long psi_race_failed;		/* pressure-file open() failed for the whole sub-mode */
};

#endif /* _TRINITY_STATS_SUBSYS_CGROUP_CHURN_H */
