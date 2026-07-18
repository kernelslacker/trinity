#ifndef _TRINITY_STATS_SUBSYS_UMOUNT_RACE_H
#define _TRINITY_STATS_SUBSYS_UMOUNT_RACE_H

struct umount_race_stats {
	/* umount_race childop counters */
	unsigned long runs;		/* total umount_race invocations */
	unsigned long picks;	/* cycles with an eligible pool entry */
	unsigned long forks;	/* accessor helpers successfully forked */
	unsigned long umounts;	/* umount2() returned 0 */
	unsigned long umount_failed;/* umount2() returned -1 (incl. expected EPERM) */
	unsigned long setup_failed;	/* fork() returned -1 */
};

#endif /* _TRINITY_STATS_SUBSYS_UMOUNT_RACE_H */
