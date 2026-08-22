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
	 *      is_child_making_progress() pass that finds diff >= REAP_STALL_THRESHOLD_S s for
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

	/* Wedge events split by whether the block was expected.
	 *
	 *  expected_block_kills
	 *      Child sat in a NEED_ALARM syscall in interruptible sleep past
	 *      the stall threshold -- read() on an idle fd, clock_nanosleep(),
	 *      rt_sigtimedwait().  Killed silently: no stuck-child scream, no
	 *      /proc stack, no fd topology.  It is the overwhelmingly common
	 *      case and narrating it buries the other kind.
	 *  unexpected_wedges
	 *      Everything else -- 'D' state, a childop, a syscall with no
	 *      NEED_ALARM flag, or a record we could not read.  These still
	 *      get the full report; this counter is the denominator that says
	 *      how much of the log is worth reading.
	 *
	 * Both latched per child via childdata.dstate_diag_dumped, so they
	 * count wedge events rather than watchdog ticks.  Same RELAXED
	 * add-fetch as the arrays above. */
	unsigned long expected_block_kills;
	unsigned long unexpected_wedges;

	/* Subset of expected_block_kills where the child had SIGALRM
	 * blocked at wedge time.  Every syscall counted in
	 * expected_block_kills carries NEED_ALARM, so the dispatcher armed
	 * alarm(1) before it and the call should have returned EINTR a
	 * second later.  It did not.  A fuzzed rt_sigprocmask(2) blocking
	 * SIGALRM is the leading explanation -- the disposition is
	 * repaired before arming, the mask is not -- and this counter is
	 * how that stops being a theory.  If it tracks
	 * expected_block_kills, the inner watchdog is being defeated and
	 * every wedge is costing 30 seconds of a child slot instead of
	 * one. */
	unsigned long expected_block_sigalrm_blocked;
};

#endif /* _TRINITY_STATS_SUBSYS_SYSCALL_WEDGE_H */
