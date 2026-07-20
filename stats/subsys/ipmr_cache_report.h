#ifndef _TRINITY_STATS_SUBSYS_IPMR_CACHE_REPORT_H
#define _TRINITY_STATS_SUBSYS_IPMR_CACHE_REPORT_H

/*
 * ipmr_cache_report childop counters.  Bespoke (non-category) RAW
 * group.  All bumps RELAXED on shm->stats.  The surrounding struct
 * stats_s composes an instance of struct ipmr_cache_report_stats as
 * its "ipmr_cache_report" member.
 */
struct ipmr_cache_report_stats {
	unsigned long iters;		/* per-iteration loop body entries */
	unsigned long eperm;		/* MRT_INIT returned -EPERM (CAP_NET_ADMIN gate) */
	unsigned long emit_ok;		/* sendto a NOCACHE multicast group succeeded */
};

#endif	/* _TRINITY_STATS_SUBSYS_IPMR_CACHE_REPORT_H */
