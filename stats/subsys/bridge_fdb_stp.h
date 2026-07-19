#ifndef _TRINITY_STATS_SUBSYS_BRIDGE_FDB_STP_H
#define _TRINITY_STATS_SUBSYS_BRIDGE_FDB_STP_H

struct bridge_fdb_stp_stats {
	/* bridge_fdb_stp childop counters */
	unsigned long runs;		/* total bridge_fdb_stp invocations */
	unsigned long setup_failed;	/* unshare(CLONE_NEWNET) / rtnl_open / bridge latched */
	unsigned long bridge_create_ok;	/* RTM_NEWLINK type=bridge accepted */
	unsigned long veth_create_ok;	/* RTM_NEWLINK type=veth accepted (per pair) */
	unsigned long raw_send_ok;	/* AF_PACKET sendto on enslaved port returned >0 */
	unsigned long stp_toggle_ok;	/* /sys/.../bridge/stp_state write succeeded */
	unsigned long fdb_del_ok;	/* RTM_DELNEIGH on a learned fdb entry accepted */
	unsigned long link_del_ok;	/* RTM_DELLINK on bridge accepted */
	unsigned long bridge_vlan_mass_runs;		/* mass-VLAN-add sub-mode invocations */
	unsigned long bridge_vlan_mass_max_n;		/* largest IFLA_BRIDGE_VLAN_INFO entry count attempted in one msg */
	unsigned long bridge_vlan_mass_enotbufs;	/* sendmsg -ENOBUFS / -EMSGSIZE on the oversize bulk message */
};

#endif /* _TRINITY_STATS_SUBSYS_BRIDGE_FDB_STP_H */
