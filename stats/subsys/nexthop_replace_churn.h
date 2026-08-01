#ifndef _TRINITY_STATS_SUBSYS_NEXTHOP_REPLACE_CHURN_H
#define _TRINITY_STATS_SUBSYS_NEXTHOP_REPLACE_CHURN_H

struct nexthop_replace_churn_stats {
	/* nexthop_replace_churn childop counters */
	unsigned long runs;			/* total invocations */
	unsigned long setup_failed;		/* userns/rtnl/nh setup rejected */
	unsigned long nh_setup_ok;		/* target NHA_ID installed */
	unsigned long sentinel_ok;		/* IPv6 /128 route bound via RTA_NH_ID */
	unsigned long replace_single_ok;	/* NLM_F_REPLACE single-nh accepted */
	unsigned long replace_group_ok;		/* NLM_F_REPLACE group form accepted */
	unsigned long route_add_ok;		/* worker RTM_NEWROUTE accepted */
	unsigned long route_del_ok;		/* worker RTM_DELROUTE accepted */
	unsigned long teardown_ok;		/* target RTM_DELNEXTHOP accepted */
};

#endif /* _TRINITY_STATS_SUBSYS_NEXTHOP_REPLACE_CHURN_H */
