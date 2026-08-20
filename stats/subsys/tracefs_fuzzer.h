#ifndef _TRINITY_STATS_SUBSYS_TRACEFS_FUZZER_H
#define _TRINITY_STATS_SUBSYS_TRACEFS_FUZZER_H

/* tracefs_fuzzer childop counters, per-ARM, split by outcome into
 * open-fail (tracefs not mounted, EACCES, ENOENT on a per-event
 * enable that was unloaded mid-run), write-fail (EINVAL on a
 * malformed probe spec, EBUSY, ...) and write-OK (the bytes
 * actually reached the kernel parser), so the dump shows real
 * reach into each tracefs surface.  write_fail + write_ok sum
 * to the per-ARM total; open_fail additionally distinguishes
 * open failures. */
struct tracefs_fuzzer_stats {
	unsigned long kprobe_open_fail;		/* writes to kprobe_events */
	unsigned long kprobe_write_fail;
	unsigned long kprobe_write_ok;
	unsigned long uprobe_open_fail;		/* writes to uprobe_events */
	unsigned long uprobe_write_fail;
	unsigned long uprobe_write_ok;
	unsigned long filter_open_fail;		/* writes to set_ftrace_filter/notrace/graph */
	unsigned long filter_write_fail;
	unsigned long filter_write_ok;
	unsigned long event_enable_open_fail;	/* writes to events subsystem enable files */
	unsigned long event_enable_write_fail;
	unsigned long event_enable_write_ok;
	unsigned long misc_open_fail;		/* trace_options, current_tracer, etc. */
	unsigned long misc_write_fail;
	unsigned long misc_write_ok;

	unsigned long dynevent_open_fail;	/* writes to dynamic_events (eprobes) */
	unsigned long dynevent_write_fail;
	unsigned long dynevent_write_ok;

	unsigned long set_event_open_fail;	/* writes to set_event (top-level event selector) */
	unsigned long set_event_write_fail;
	unsigned long set_event_write_ok;

	/* Disable-arm oracle: set_event_post_disable_count is a gauge —
	 * each successful !-prefixed write stores (not adds) the surviving
	 * enabled-event count so the most-recent snapshot is always readable.
	 * set_event_disable_arms is the denominator: incremented once per
	 * disable-arm oracle firing so post_disable_count / disable_arms
	 * is interpretable.  set_event_disable_reenabled counts how many
	 * times the re-enable teardown (writing "*:") ran to restore the
	 * set; all three together let an operator detect net erosion vs
	 * successful restores.
	 */
	unsigned long set_event_post_disable_count;
	unsigned long set_event_disable_arms;
	unsigned long set_event_disable_reenabled;

	/* count_set_event_lines() open-fail counter: incremented when
	 * open(set_event, O_RDONLY) fails so the caller can distinguish
	 * a readback failure from a genuine zero-event count. */
	unsigned long set_event_readback_fail;

	/* Number of dispatches inside tracefs_fuzzer that landed on a
	 * function-tracer-subset op (set_ftrace_filter / set_ftrace_notrace /
	 * set_graph_function / current_tracer) but were short-circuited
	 * because the running kernel was built without CONFIG_FTRACE
	 * (current_tracer absent at init probe).  Static-event-tree paths
	 * keep running on the same kernel; this counts only the wasted
	 * function-tracer slots.  No live producer today; the counter is
	 * carved forward so a future ftrace-subset dispatcher landing has a
	 * pre-approved home. */
	unsigned long ftrace_subset_skipped;

	/* Runtime cap-denied probe (set in child context, after cap-drop).
	 *
	 * tracefs_fuzzer_init() probes tracefs_root with access(F_OK) in the
	 * PARENT before cap-drop, where the invoking user (typically root)
	 * can always see the mount.  In the child, after uid/cap-drop to the
	 * fuzz user, write access to tracefs may be denied (EACCES/EPERM)
	 * even though the mount is present.  The init-time F_OK check
	 * correctly sets tracefs_available=true, so the childop dispatches,
	 * but every write attempt returns OUTCOME_OPEN_FAIL.
	 *
	 * runtime_cap_denied is incremented once per child (COW latch) the
	 * first time tracefs_fuzzer() is invoked from that child, by probing
	 * access(tracefs_root/tracing_on, W_OK) AFTER cap-drop.  When this
	 * counter is non-zero and no write-ok counters accumulated, the arm
	 * is cap-dead and dump_stats_dead_arm_check() emits RUNTIME_DEAD_ARM
	 * for the childop. */
	unsigned long runtime_cap_denied;
};


#endif /* _TRINITY_STATS_SUBSYS_TRACEFS_FUZZER_H */
