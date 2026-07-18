#ifndef _TRINITY_STATS_SUBSYS_VDSO_RACE_H
#define _TRINITY_STATS_SUBSYS_VDSO_RACE_H

struct vdso_race_stats {
	/* vdso_mremap_race childop counters */
	unsigned long runs;		/* total vdso_mremap_race invocations */
	unsigned long mutations;	/* mutator-side mremap/mprotect/madvise/munmap issued */
	unsigned long helper_segvs;	/* spinner helper killed by SIGSEGV/SIGBUS */
};

#endif /* _TRINITY_STATS_SUBSYS_VDSO_RACE_H */
