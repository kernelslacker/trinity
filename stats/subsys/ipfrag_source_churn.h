#ifndef _TRINITY_STATS_SUBSYS_IPFRAG_SOURCE_CHURN_H
#define _TRINITY_STATS_SUBSYS_IPFRAG_SOURCE_CHURN_H

struct ipfrag_source_churn_stats {
	/* ipfrag_source_churn childop counters */
	unsigned long runs;			/* total ipfrag_source_churn invocations */
	unsigned long packets_sent_ok;		/* raw IPv4 fragment sendto returned >0 */
	unsigned long send_failed;		/* sendto returned <=0 (queue full / EPERM / etc.) */
	unsigned long unique_srcs;		/* fragment pairs emitted with a fresh source IP */
};

#endif /* _TRINITY_STATS_SUBSYS_IPFRAG_SOURCE_CHURN_H */
