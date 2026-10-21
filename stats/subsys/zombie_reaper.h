#ifndef _TRINITY_STATS_SUBSYS_ZOMBIE_REAPER_H
#define _TRINITY_STATS_SUBSYS_ZOMBIE_REAPER_H

/*
 * zombie-reaper accounting.  Slots held in zombie-pending state because
 * the kernel has not released the task yet and may still run it to
 * write into childdata: an unkillable D-state task, or a stopped child.
 * Reusing a slot before the kernel tears the task down lets those late
 * writes corrupt the replacement child.
 *
 * Bespoke (non-category) RAW group.  All bumps RELAXED on shm->stats.
 * The surrounding struct stats_s composes an instance of struct
 * zombie_reaper_stats as its "zombie_reaper" member.
 */
struct zombie_reaper_stats {
	unsigned long slots_pending;	/* current count (gauge) */
	unsigned long reaped;		/* total successfully reaped */
	unsigned long timed_out;	/* timed out waiting for kernel release */
	/*
	 * Slots permanently removed from the active fleet because the
	 * kernel did not release the D-state task within
	 * ZOMBIE_REAP_TIMEOUT_SEC.  These are never recycled; the fleet
	 * shrinks by one per quarantined slot for the rest of the run.
	 * Once zombie_quarantine_threshold() slots are quarantined the
	 * run stops with EXIT_KERNEL_STUCK; reap-zombie.c counts them in
	 * parent memory, not from this shm copy.
	 */
	unsigned long quarantined;
};

#endif	/* _TRINITY_STATS_SUBSYS_ZOMBIE_REAPER_H */
