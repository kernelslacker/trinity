#ifndef _TRINITY_STATS_SUBSYS_MULTIPATH_LINKDOWN_REBALANCE_H
#define _TRINITY_STATS_SUBSYS_MULTIPATH_LINKDOWN_REBALANCE_H

struct multipath_linkdown_rebalance_stats {
	/* multipath_linkdown_rebalance childop counters */
	unsigned long runs;			/* total invocations */
	unsigned long setup_failed;		/* rtnl/fork/userns setup failed */
	unsigned long v4_runs;			/* invocation chose the IPv4 arm */
	unsigned long v6_runs;			/* invocation chose the IPv6 arm */
	unsigned long legs_ok;			/* both veth legs up + addressed */
	unsigned long route_ok;			/* initial multipath route installed */
	unsigned long rebalance_triggers;	/* NLM_F_REPLACE re-runs accepted */
	unsigned long flip_writes;		/* sysctl 1<->0 writes issued */
	unsigned long completed_ok;		/* full cycle reached worker reap */
};

#endif /* _TRINITY_STATS_SUBSYS_MULTIPATH_LINKDOWN_REBALANCE_H */
