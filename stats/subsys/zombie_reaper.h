#ifndef _TRINITY_STATS_SUBSYS_ZOMBIE_REAPER_H
#define _TRINITY_STATS_SUBSYS_ZOMBIE_REAPER_H

/*
 * zombie-reaper accounting.  Slots held in zombie-pending state because
 * the kernel still has the unkillable D-state task around and may yet
 * wake it to write into childdata.  Reusing a slot before the kernel
 * tears the task down lets the post-wake writes corrupt the replacement
 * child.
 *
 * Bespoke (non-category) RAW group.  All bumps RELAXED on shm->stats.
 * The surrounding struct stats_s composes an instance of struct
 * zombie_reaper_stats as its "zombie_reaper" member.
 */
struct zombie_reaper_stats {
	unsigned long slots_pending;	/* current count (gauge) */
	unsigned long reaped;		/* total successfully reaped */
	unsigned long timed_out;	/* force-reused after timeout */
};

#endif	/* _TRINITY_STATS_SUBSYS_ZOMBIE_REAPER_H */
