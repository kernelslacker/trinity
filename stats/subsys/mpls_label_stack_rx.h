#ifndef _TRINITY_STATS_SUBSYS_MPLS_LABEL_STACK_RX_H
#define _TRINITY_STATS_SUBSYS_MPLS_LABEL_STACK_RX_H

struct mpls_label_stack_rx_stats {
	/* mpls_label_stack_rx childop counters */
	unsigned long runs;			/* total mpls_label_stack_rx invocations */
	unsigned long setup_failed;		/* userns_run_in_ns / rtnl_open / lo lookup failed (incl. kind-latched or !CONFIG_MPLS_ROUTING) */
	unsigned long config_ok;		/* net.mpls.platform_labels + conf.lo.input writes accepted */
	unsigned long config_failed;	/* sysctl open/write rejected (any errno) */
	unsigned long link_up_ok;		/* RTM_SETLINK IFF_UP on lo accepted */
	unsigned long packet_sent_ok;	/* sendto on AF_PACKET with ETH_P_MPLS_UC frame returned >0 */
};

#endif /* _TRINITY_STATS_SUBSYS_MPLS_LABEL_STACK_RX_H */
