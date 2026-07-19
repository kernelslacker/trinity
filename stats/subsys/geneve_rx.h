#ifndef _TRINITY_STATS_SUBSYS_GENEVE_RX_H
#define _TRINITY_STATS_SUBSYS_GENEVE_RX_H

struct geneve_rx_stats {
	/* geneve_rx childop counters */
	unsigned long runs;			/* total geneve_rx invocations */
	unsigned long setup_failed;		/* userns_run_in_ns / rtnl_open failed (incl. kind-latched or !CONFIG_GENEVE) */
	unsigned long link_create_ok;		/* RTM_NEWLINK kind="geneve" accepted */
	unsigned long link_create_failed;	/* RTM_NEWLINK rejected (any errno) */
	unsigned long link_up_ok;		/* RTM_SETLINK IFF_UP on the geneve dev accepted */
	unsigned long packet_sent_ok;		/* sendto on IPPROTO_RAW with UDP/GENEVE frame returned >0 */
	unsigned long link_del_ok;		/* RTM_DELLINK on teardown accepted */
};

#endif /* _TRINITY_STATS_SUBSYS_GENEVE_RX_H */
