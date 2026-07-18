#ifndef _TRINITY_STATS_SUBSYS_OVS_TUNNEL_VPORT_CHURN_H
#define _TRINITY_STATS_SUBSYS_OVS_TUNNEL_VPORT_CHURN_H

struct ovs_tunnel_vport_churn_stats {
	/* ovs_tunnel_vport_churn childop counters */
	unsigned long runs;		/* total ovs_tunnel_vport_churn invocations */
	unsigned long setup_failed;	/* genl open / family resolve / dp create latched */
	unsigned long create_ok;		/* OVS_VPORT_CMD_NEW accepted */
	unsigned long delete_ok;		/* OVS_VPORT_CMD_DEL accepted */
	unsigned long race_dellink_attempted;	/* RTM_DELLINK racer fired at helper netdev */
};

#endif /* _TRINITY_STATS_SUBSYS_OVS_TUNNEL_VPORT_CHURN_H */
