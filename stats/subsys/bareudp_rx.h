#ifndef _TRINITY_STATS_SUBSYS_BAREUDP_RX_H
#define _TRINITY_STATS_SUBSYS_BAREUDP_RX_H

struct bareudp_rx_stats {
	/* bareudp_rx childop counters */
	unsigned long runs;			/* total bareudp_rx invocations */
	unsigned long setup_failed;		/* userns_run_in_ns / rtnl_open failed (incl. kind-latched or !CONFIG_BAREUDP) */
	unsigned long link_create_ok;	/* RTM_NEWLINK kind="bareudp" accepted */
	unsigned long link_create_failed;	/* RTM_NEWLINK rejected (any errno) */
	unsigned long link_up_ok;		/* RTM_SETLINK IFF_UP on the bareudp dev accepted */
	unsigned long packet_sent_ok;	/* sendto on IPPROTO_RAW with UDP/inner-L3 frame returned >0 */
	unsigned long link_del_ok;		/* RTM_DELLINK on teardown accepted */
};

#endif /* _TRINITY_STATS_SUBSYS_BAREUDP_RX_H */
