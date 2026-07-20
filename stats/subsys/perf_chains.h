#ifndef _TRINITY_STATS_SUBSYS_PERF_CHAINS_H
#define _TRINITY_STATS_SUBSYS_PERF_CHAINS_H

struct perf_chains_stats {
	/* perf_event_chains childop counters */
	unsigned long runs;		/* total invocations */
	unsigned long groups_created;	/* group leader fd opened successfully */
	unsigned long ioctl_ops;	/* PERF_EVENT_IOC_* calls made */

	/*
	 * perf_event_chains ensure_discovery() observed pmu_count == 0
	 * after the discover_pmus() sweep, so the childop is disabling
	 * itself for the remainder of this child's life.  The original
	 * shape called outputerr from inside a pmu_warned_unsupported
	 * one-shot gate (one log per child), but the dup2 redirect to
	 * /dev/null in init_child swallowed the message.  Bumping a
	 * counter under the same one-shot gate leaves a survivor signal:
	 * a high count is the fingerprint of a sysctl-locked-down host
	 * or a kernel build with the perf subsystem absent.
	 */
	unsigned long pmu_unsupported;
};

#endif /* _TRINITY_STATS_SUBSYS_PERF_CHAINS_H */
