#ifndef _TRINITY_STATS_SUBSYS_UID_CHANGE_H
#define _TRINITY_STATS_SUBSYS_UID_CHANGE_H

struct uid_change_stats {
	/* Bumped each time check_uid sees the child's uid drift away from
	 * orig_uid + overflowuid; was previously a hard bail
	 * (EXIT_UID_CHANGED) but logged + continued for non-root drifts
	 * since 2026-05-09.  The drift is almost always a fuzzed
	 * setresuid/setreuid/setfsuid succeeding inside an unshared user
	 * namespace -- interesting coverage, not a danger -- so the run
	 * keeps going.  A drift to uid==0 (root) is still a hard bail
	 * via EXIT_UID_CHANGED, since subsequent fuzz syscalls at elevated
	 * privilege could damage the host. */
	unsigned long logged;
};

#endif /* _TRINITY_STATS_SUBSYS_UID_CHANGE_H */
