#ifndef _TRINITY_STATS_SUBSYS_OBSCURE_AF_CHURN_H
#define _TRINITY_STATS_SUBSYS_OBSCURE_AF_CHURN_H

struct obscure_af_churn_stats {
	/* obscure_af_churn childop counters.  Per-pattern arrays are
	 * indexed by enum abuse_pattern (childops/net/obscure-af-churn.c);
	 * NR_AP is currently 6.  Sized at 8 to leave headroom for a
	 * couple more patterns without re-cutting the shm layout. */
	unsigned long runs;
	unsigned long no_viable_pf;	/* every pf attempt was no_domains[] / proto NULL */
	unsigned long pattern_runs[8];
	unsigned long pattern_kernel_rejected[8];
	unsigned long pattern_unexpected_success[8];
};

#endif /* _TRINITY_STATS_SUBSYS_OBSCURE_AF_CHURN_H */
