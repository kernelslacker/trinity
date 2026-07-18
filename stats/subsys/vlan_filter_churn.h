#ifndef _TRINITY_STATS_SUBSYS_VLAN_FILTER_CHURN_H
#define _TRINITY_STATS_SUBSYS_VLAN_FILTER_CHURN_H

struct vlan_filter_churn_stats {
	/* vlan_filter_churn childop counters */
	unsigned long runs;			/* total vlan_filter_churn invocations */
	unsigned long setup_failed;		/* userns / rtnl_open / veth or vlan probe latched */
	unsigned long veth_create_ok;		/* RTM_NEWLINK type=veth base pair accepted */
	unsigned long vlan_add_ok;		/* RTM_NEWLINK type=vlan IFLA_VLAN_ID accepted (vlan_vid_add drive) */
	unsigned long vlan_del_ok;		/* RTM_DELLINK on vlan child accepted (vlan_vid_del drive) */
};

#endif /* _TRINITY_STATS_SUBSYS_VLAN_FILTER_CHURN_H */
