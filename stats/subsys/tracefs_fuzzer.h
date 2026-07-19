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
};

#endif /* _TRINITY_STATS_SUBSYS_TRACEFS_FUZZER_H */
