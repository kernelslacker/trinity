#pragma once

#include "kmsg-monitor.h"

/* Sub-struct of struct kcov_shared, embedded as .kmsg.
 * Layout is offset-sensitive; do not reorder fields.
 * New fields must be appended after fires_per_kind[]. */

struct kcov_kmsg {
	/* Flat per-event WARN-fires counter, bumped from kmsg_monitor_thread
	 * each time classify_kmsg_event() returns a non-UNKNOWN kind --
	 * every classified WARN / BUG / OOPS / RCU / lockdep splat counts
	 * once regardless of flavour.  Cohort attribution against
	 * cmp_hints_chaos_active happens at bandit window close in
	 * maybe_rotate_strategy: a delta over the window is bucketed into
	 * the chaos-on or chaos-off slot per arm, so the operator can see
	 * whether chaos-suppressed cmp-hint generation actually produces
	 * more kernel diagnostic fires than the baseline.  Flat (no
	 * per-flavour split) for V2 -- per-flavour breakdown is V2.1 once
	 * any signal exists to slice. */
	unsigned long kmsg_warn_fires;
	/* Per-kind breakdown of kmsg_warn_fires.  Indexed by enum kmsg_event_kind
	 * (values 1..NR_KMSG_KINDS-1; index 0 / KMSG_EVENT_UNKNOWN is never
	 * written).  Bumped atomically alongside kmsg_warn_fires so the two
	 * series stay consistent.  Consumers wanting the total flat count
	 * continue to read kmsg_warn_fires; this array adds the per-kind split
	 * required to separate mm-corruption (KMSG_MM_CORRUPT) from benign
	 * INFO events and other warn flavours in bandit cohort attribution. */
	unsigned long fires_per_kind[NR_KMSG_KINDS];
};
