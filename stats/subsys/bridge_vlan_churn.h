#ifndef _TRINITY_STATS_SUBSYS_BRIDGE_VLAN_CHURN_H
#define _TRINITY_STATS_SUBSYS_BRIDGE_VLAN_CHURN_H

struct bridge_vlan_churn_stats {
	/* bridge_vlan_churn childop counters */
	unsigned long runs;			/* total bridge_vlan_churn invocations */
	unsigned long setup_failed;		/* unshare / rtnl_open / bridge probe latched */
	unsigned long bridge_create_ok;	/* RTM_NEWLINK type=bridge IFLA_BR_VLAN_FILTERING=1 accepted */
	unsigned long veth_create_ok;		/* RTM_NEWLINK type=veth accepted (per pair) */
	unsigned long vlan_add_ok;		/* RTM_SETLINK IFLA_BRIDGE_VLAN_INFO add accepted on a port */
	unsigned long vlan_del_ok;		/* RTM_DELLINK IFLA_BRIDGE_VLAN_INFO del accepted mid-traffic */
	unsigned long tunnel_add_ok;		/* RTM_SETLINK IFLA_BRIDGE_VLAN_TUNNEL_INFO add accepted */
	unsigned long mst_set_ok;		/* RTM_SETLINK IFLA_PROTINFO IFLA_BRPORT_MST_ENTRY set accepted */
	unsigned long raw_send_ok;		/* AF_PACKET sendto with 802.1Q tag returned >0 */
};

#endif /* _TRINITY_STATS_SUBSYS_BRIDGE_VLAN_CHURN_H */
