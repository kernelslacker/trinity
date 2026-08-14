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

	/*
	 * star_g port-group UAF oracle.
	 *
	 * Positive-control invariant: if mdb_star_g_created and mdb_sg_created both stay
	 * 0 the builder or src-list nesting is broken; do not report a
	 * clean kernel.  star_g_arm_setup_failed covers failures in the
	 * bridge/veth setup phase before any MDB work.
	 */
	unsigned long star_g_arm_setup_failed;		/* bridge/veth setup failure before MDB */
	unsigned long mdb_star_g_created;		/* RTM_NEWMDB (*,G) EXCLUDE accepted */
	unsigned long mdb_sg_created;			/* RTM_NEWMDB (S,G) accepted (per entry) */
	unsigned long star_g_mdbe_src_list_built;	/* build_star_g_src_list_nest() successes */
	/*
	 * Positive-control: if this stays 0 after exercising the src-list path
	 * in msg-rtnl-neigh.c, the build_mdbe_src_list_into() builder is broken.
	 */
	unsigned long neigh_mdbe_src_list_built;	/* build_mdbe_src_list_into() successes */
	unsigned long star_g_mdb_before;		/* MDB entry count before oracle-A triggers */
	unsigned long star_g_mdb_after;			/* MDB entry count after oracle-A triggers */
};

#endif /* _TRINITY_STATS_SUBSYS_BRIDGE_FDB_STP_H */
