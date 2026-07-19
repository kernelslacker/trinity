#ifndef _TRINITY_STATS_SUBSYS_TIPC_LINK_CHURN_H
#define _TRINITY_STATS_SUBSYS_TIPC_LINK_CHURN_H

struct tipc_link_churn_stats {
	/* tipc_link_churn childop counters */
	unsigned long runs;		/* total tipc_link_churn invocations */
	unsigned long setup_failed;	/* modprobe / AF_TIPC / family-resolve gate failed */
	unsigned long bearer_enable_ok;	/* TIPC_NL_BEARER_ENABLE genl ack==0 */
	unsigned long sock_rdm_ok;	/* socket(AF_TIPC, SOCK_RDM) returned >=0 */
	unsigned long topsrv_connect_ok; /* SEQPACKET socket connected to TIPC_TOP_SRV */
	unsigned long sub_ports_sent;	/* TIPC_SUB_PORTS subscription sent on topsrv socket */
	unsigned long publish_ok;	/* bind() with TIPC_CLUSTER_SCOPE for publish accepted */
	unsigned long bearer_disable_ok; /* TIPC_NL_BEARER_DISABLE genl ack==0 */
};

#endif /* _TRINITY_STATS_SUBSYS_TIPC_LINK_CHURN_H */
