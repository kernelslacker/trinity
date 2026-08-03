#ifndef _TRINITY_STATS_SUBSYS_IP6MR_CHURN_H
#define _TRINITY_STATS_SUBSYS_IP6MR_CHURN_H

/*
 * ip6mr_churn childop counters.  Bespoke (non-category) RAW group.
 * All bumps RELAXED on shm->stats.  The surrounding struct stats_s
 * composes an instance of struct ip6mr_churn_stats as its
 * "ip6mr_churn" member.
 */
struct ip6mr_churn_stats {
	unsigned long iters;		/* per-iteration loop body entries */
	unsigned long eperm;		/* MRT6_INIT returned -EPERM (CAP_NET_ADMIN gate) */
	unsigned long emit_ok;		/* sendto a NOCACHE multicast group succeeded */
};

#endif	/* _TRINITY_STATS_SUBSYS_IP6MR_CHURN_H */
