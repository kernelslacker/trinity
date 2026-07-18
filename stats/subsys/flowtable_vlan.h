#ifndef _TRINITY_STATS_SUBSYS_FLOWTABLE_VLAN_H
#define _TRINITY_STATS_SUBSYS_FLOWTABLE_VLAN_H

struct flowtable_vlan_stats {
	/* flowtable_encap_vlan childop counters */
	unsigned long runs;			/* total flowtable_encap_vlan invocations */
	unsigned long setup_ok;			/* table+flowtable+chain+rule install all accepted */
	unsigned long setup_failed;		/* nl_open / veth / vlan / table / chain / rule rejected */
	unsigned long offloaded_pkts;		/* UDP send through forward chain returned >0 (offload-eligible) */
	unsigned long gso_sends;			/* TCP_NODELAY=0 + 64KB write returned >0 (GSO re-checksum path) */
	unsigned long vlan_teardown_races;	/* RTM_DELLINK on vlan child mid-burst returned 0 */
	unsigned long unsupported_latched;	/* NFT_MSG_NEWFLOWTABLE EOPNOTSUPP latched op off */
};

#endif /* _TRINITY_STATS_SUBSYS_FLOWTABLE_VLAN_H */
