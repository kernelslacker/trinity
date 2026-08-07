#ifndef _TRINITY_STATS_SUBSYS_BPF_CGROUP_ATTACH_H
#define _TRINITY_STATS_SUBSYS_BPF_CGROUP_ATTACH_H

struct bpf_cgroup_attach_stats {
	/* bpf_cgroup_attach childop counters */
	unsigned long runs;			/* total bpf_cgroup_attach invocations */
	unsigned long setup_failed;		/* cgroup open / PROG_LOAD failed */
	unsigned long prog_loaded;		/* PROG_LOAD accepted */
	unsigned long attached;		/* PROG_ATTACH accepted */
	unsigned long attach_rejected;	/* PROG_ATTACH rejected */
	unsigned long packets_sent;		/* sendto/connect ops returned >=0 */
	unsigned long detached;		/* PROG_DETACH accepted (mid-flow) */
	unsigned long post_detach_sent;	/* sendto/connect after detach returned >=0 */
	unsigned long setsockopt_hook_reach;	/* setsockopt calls that returned EFAULT — SETSOCKOPT hook confirmed */
	unsigned long getsockopt_hook_reach;	/* getsockopt calls that returned EFAULT — GETSOCKOPT hook confirmed */
	unsigned long post_detach_sockopt_reach;	/* same after PROG_DETACH; non-zero flags stale-array dispatch bug */
	unsigned long sockopt_probe_bursts;	/* SETSOCKOPT bursts where the EFAULT probe was active (~1-in-8);
					 * denominator for setsockopt_hook_reach — a zero reach is
					 * expected when this is also zero (7/8 bursts have no probe). */
	unsigned long sockopt_probe_calls;	/* individual setsockopt calls issued while the EFAULT probe was
					 * active; per-call denominator for setsockopt_hook_reach. */
};

#endif /* _TRINITY_STATS_SUBSYS_BPF_CGROUP_ATTACH_H */
