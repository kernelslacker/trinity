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
};

#endif /* _TRINITY_STATS_SUBSYS_BPF_CGROUP_ATTACH_H */
