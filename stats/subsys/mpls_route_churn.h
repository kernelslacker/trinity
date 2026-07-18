#ifndef _TRINITY_STATS_SUBSYS_MPLS_ROUTE_CHURN_H
#define _TRINITY_STATS_SUBSYS_MPLS_ROUTE_CHURN_H

struct mpls_route_churn_stats {
	/* mpls_route_churn childop counters */
	unsigned long runs;		/* total mpls_route_churn invocations */
	unsigned long label_install_ok; /* RTM_NEWROUTE family=AF_MPLS accepted (arm A) */
	unsigned long iptunnel_install_ok; /* RTM_NEWROUTE family=AF_INET + RTA_ENCAP MPLS accepted (arm B) */
	unsigned long delete_ok;	/* matching RTM_DELROUTE accepted (either arm) */
	unsigned long ns_unsupported;	/* mpls / lwtunnel latch fired (no-op for the rest of this child) */
};

#endif /* _TRINITY_STATS_SUBSYS_MPLS_ROUTE_CHURN_H */
