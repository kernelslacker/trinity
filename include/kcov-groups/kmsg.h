#pragma once

/* Sub-struct of struct kcov_shared, embedded as .kmsg.
 * Layout is offset-sensitive; do not reorder fields. */

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
};
