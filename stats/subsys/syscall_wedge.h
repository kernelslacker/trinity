#ifndef _TRINITY_STATS_SUBSYS_SYSCALL_WEDGE_H
#define _TRINITY_STATS_SUBSYS_SYSCALL_WEDGE_H

#include "syscall.h"	/* MAX_NR_SYSCALL */

struct syscall_wedge_stats {
	/* Per-syscall wedge accounting.
	 * Indexed by raw syscall nr conflated across the do32 dimension, the
	 * same shape edges_per_syscall_bandit[] / frontier_picks_per_syscall[]
	 * use.  The existing per-syscall top-N dump path
	 * (top_syscalls_periodic_dump) already scans only the 64-bit table
	 * under biarch to avoid the 32/64 collision in nr; the wedge top-N row
	 * follows the same convention.
	 *
	 *  count[nr]
	 *      Bumped once per stuck-child detection event, at the first
	 *      is_child_making_progress() pass that finds diff >= 30 s for
	 *      this child.  Latched per-child via childdata.wedge_accounted so
	 *      a child that stays wedged across many watchdog ticks counts as
	 *      one event, not one per tick.  RELAXED add-fetch -- diagnostic,
	 *      not an event log.
	 *  total_us[nr]
	 *      Cumulative microseconds across all wedge events for this
	 *      syscall.  Added in reap_child() once the kernel has finally
	 *      released the slot (or the unkillable-D-state path forces slot
	 *      reuse via register_zombie_slot), so the duration reflects the
	 *      full time the slot was unreusable.  CLOCK_MONOTONIC so an NTP
	 *      step cannot regress the elapsed; clamped at the read site so a
	 *      reordered read of the start tp cannot underflow to ~ULLONG_MAX.
	 *      RELAXED add-fetch.
	 *
	 * Surfaced via dump_stats_top_wedging_syscalls() at shutdown only --
	 * not on the JSON path (the array is 2 * MAX_NR_SYSCALL * 8 = 16 KiB,
	 * same rationale as edges_per_syscall_bandit / frontier_picks_per_
	 * syscall which also stay text-only). */
	unsigned long count[MAX_NR_SYSCALL];
	unsigned long long total_us[MAX_NR_SYSCALL];
};

#endif /* _TRINITY_STATS_SUBSYS_SYSCALL_WEDGE_H */
