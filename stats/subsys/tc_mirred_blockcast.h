#ifndef _TRINITY_STATS_SUBSYS_TC_MIRRED_BLOCKCAST_H
#define _TRINITY_STATS_SUBSYS_TC_MIRRED_BLOCKCAST_H

struct tc_mirred_blockcast_stats {
	/* tc_mirred_blockcast childop counters */
	unsigned long runs;		/* total tc_mirred_blockcast invocations */
	unsigned long setup_failed;	/* unshare / NETLINK_ROUTE open latched */
	unsigned long qdisc_ok;	/* clsact + TCA_EGRESS_BLOCK install accepted (per device) */
	unsigned long qdisc_fail;	/* clsact + TCA_EGRESS_BLOCK install rejected */
	unsigned long filter_ok;	/* matchall+mirred(blockid) on shared block accepted */
	unsigned long filter_fail;	/* matchall+mirred(blockid) on shared block rejected */
	unsigned long packet_sent_ok;	/* loopback UDP sendto on A bound dummy returned >0 */
};

#endif /* _TRINITY_STATS_SUBSYS_TC_MIRRED_BLOCKCAST_H */
