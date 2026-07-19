#ifndef _TRINITY_STATS_SUBSYS_FOU_GUE_MCAST_RX_H
#define _TRINITY_STATS_SUBSYS_FOU_GUE_MCAST_RX_H

struct fou_gue_mcast_rx_stats {
	/* fou_gue_mcast_rx childop counters */
	unsigned long runs;			/* total fou_gue_mcast_rx invocations */
	unsigned long setup_failed;		/* userns_run_in_ns / genl_open("fou") open failed (incl. kind-latched or !CONFIG_NET_FOU) */
	unsigned long port_install_ok;		/* FOU_CMD_ADD installing a FOU/GUE receive port accepted */
	unsigned long port_install_failed;	/* FOU_CMD_ADD rejected (any errno) */
	unsigned long packet_sent_ok;		/* sendto on IPPROTO_RAW (v4 or v6) with UDP-encap frame returned >0 */
	unsigned long port_delete_ok;		/* FOU_CMD_DEL on teardown accepted */
};

#endif /* _TRINITY_STATS_SUBSYS_FOU_GUE_MCAST_RX_H */
