#ifndef _TRINITY_STATS_SUBSYS_SYSFS_STRING_RACE_H
#define _TRINITY_STATS_SUBSYS_SYSFS_STRING_RACE_H

/*
 * sysfs_string_race childop counters.  Two fork()ed writer children
 * race concurrent pwrite() calls against a curated sysfs attribute
 * to exercise .store() teardown / re-entry paths.  Counters are
 * diagnostic only; each bump RELAXED on shm->stats.
 *
 * setup_failed:      no curated target was writable (probe latched unsupported)
 * target_missing:    per-iteration open of a previously-writable target failed
 * target_used:       both writer children spawned against a target
 * fork_failed:       fork() of a writer child failed (EAGAIN / RLIMIT)
 * writes_ok:         child pwrite() returned >0 (.store() accepted)
 * writes_failed:     child pwrite() returned <=0 (EINVAL / EBUSY / etc.)
 *
 * The surrounding struct stats_s composes an instance of struct
 * sysfs_string_race_stats as its "sysfs_string_race" member.
 */
struct sysfs_string_race_stats {
	unsigned long runs;
	unsigned long setup_failed;
	unsigned long target_missing;
	unsigned long target_used;
	unsigned long fork_failed;
	unsigned long writes_ok;
	unsigned long writes_failed;
};

#endif	/* _TRINITY_STATS_SUBSYS_SYSFS_STRING_RACE_H */
