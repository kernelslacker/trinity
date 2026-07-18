#ifndef _TRINITY_STATS_SUBSYS_BPF_LIFECYCLE_H
#define _TRINITY_STATS_SUBSYS_BPF_LIFECYCLE_H

struct bpf_lifecycle_stats {
	/* bpf_lifecycle childop counters */
	unsigned long runs;		/* total bpf_lifecycle invocations */
	unsigned long progs_loaded;	/* successful BPF_PROG_LOAD */
	unsigned long verifier_rejects;	/* PROG_LOAD rejected (non-EPERM) */
	unsigned long attached;		/* successful attach (either combo) */
	unsigned long attach_failed;	/* attach syscall failed */
	unsigned long triggered;		/* trigger phase reached */
	unsigned long eperm;		/* PROG_LOAD/ATTACH denied */
};

#endif /* _TRINITY_STATS_SUBSYS_BPF_LIFECYCLE_H */
