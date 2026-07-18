#ifndef _TRINITY_STATS_SUBSYS_IGMP_MLD_SOURCE_CHURN_H
#define _TRINITY_STATS_SUBSYS_IGMP_MLD_SOURCE_CHURN_H

struct igmp_mld_source_churn_stats {
	/* igmp_mld_source_churn childop counters */
	unsigned long runs;		/* total igmp_mld_source_churn invocations */
	unsigned long setup_failed;	/* socket / bind / probe latched */
	unsigned long join_ok;		/* MCAST_JOIN_SOURCE_GROUP accepted */
	unsigned long leave_ok;		/* MCAST_LEAVE_SOURCE_GROUP accepted mid-stream */
	unsigned long block_ok;		/* MCAST_BLOCK_SOURCE accepted (INCLUDE->EXCLUDE flip) */
	unsigned long msfilter_ok;	/* MCAST_MSFILTER bulk replace accepted */
	unsigned long drop_ok;		/* IP_DROP_MEMBERSHIP / IPV6_DROP_MEMBERSHIP accepted */
	unsigned long send_ok;		/* sender datagram returned >0 */
};

#endif /* _TRINITY_STATS_SUBSYS_IGMP_MLD_SOURCE_CHURN_H */
