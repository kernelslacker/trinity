#ifndef _TRINITY_STATS_SUBSYS_BRIDGE_CT_H
#define _TRINITY_STATS_SUBSYS_BRIDGE_CT_H

struct bridge_ct_stats {
	/* bridge_conntrack_churn childop counters */
	unsigned long runs;			/* total bridge_conntrack_churn invocations */
	unsigned long flushes;		/* IPCTNL_MSG_CT_FLUSH messages emitted */
	unsigned long pkts_sent;		/* UDP packets pushed via veth peer end */
};

#endif /* _TRINITY_STATS_SUBSYS_BRIDGE_CT_H */
