#ifndef _TRINITY_STATS_SUBSYS_CPU_HOTPLUG_H
#define _TRINITY_STATS_SUBSYS_CPU_HOTPLUG_H

struct cpu_hotplug_stats {
	/* cpu_hotplug_rider childop counters.
	 *
	 * Each per-iteration sysfs dispatch goes through two gates -- open()
	 * on /sys/.../cpuN/online (the file is mode 644 so a non-root child
	 * that has dropped uid+caps gets -EACCES here without the kernel ever
	 * seeing a write), and write() (which the kernel can still reject
	 * with -EACCES/-EPERM even on a successful open, plus genuine errno
	 * paths like -EBUSY on a torn-down CPU).  The single eperm tally
	 * conflated those, so the dump could not show that the
	 * online/offline write path is ~zero on a normal host: open() never
	 * lets the dispatch reach it.  Split into:
	 *   open_eperm   - open(O_WRONLY) returned -EACCES/-EPERM (the
	 *                  dominant non-root outcome).
	 *   write_eperm  - open() succeeded, write() returned -EACCES/-EPERM
	 *                  (rare; kernel-side permission failure).
	 *   write_ok     - open() succeeded, write() returned 1 (the byte
	 *                  reached the cpu_subsys_online_store handler).
	 * Non-EPERM failures (open ENOENT mid-unplug, write EBUSY, ...) are
	 * counted in sysfs_writes but not in any outcome bucket, so a gap
	 * between sysfs_writes and the bucket sum is itself visible. */
	unsigned long runs;			/* total cpu_hotplug_rider invocations */
	unsigned long affinity_calls;	/* sched_setaffinity/sched_setattr issued */
	unsigned long sysfs_writes;		/* attempted writes to cpuN online file */
	unsigned long open_eperm;		/* open(O_WRONLY) returned -EACCES/-EPERM */
	unsigned long write_eperm;		/* open OK, write returned -EACCES/-EPERM */
	unsigned long write_ok;		/* write() to cpuN/online succeeded */
	unsigned long actual_offlines;	/* real offline+online cycles (root only) */
};

#endif /* _TRINITY_STATS_SUBSYS_CPU_HOTPLUG_H */
