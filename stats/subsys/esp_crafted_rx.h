#ifndef _TRINITY_STATS_SUBSYS_ESP_CRAFTED_RX_H
#define _TRINITY_STATS_SUBSYS_ESP_CRAFTED_RX_H

struct esp_crafted_rx_stats {
	/* esp_crafted_rx childop counters */
	unsigned long runs;			/* total esp_crafted_rx invocations */
	unsigned long setup_failed;		/* userns_run_in_ns / NETLINK_XFRM open failed (incl. kind-latched or !CONFIG_XFRM) */
	unsigned long sa_install_ok;		/* XFRM_MSG_NEWSA installing an inbound null-cipher/null-auth ESP SA accepted */
	unsigned long sa_install_failed;		/* XFRM_MSG_NEWSA rejected (any errno) */
	unsigned long packet_sent_ok;		/* sendto on IPPROTO_RAW (v4 or v6) returned >0 */
	unsigned long sa_delete_ok;		/* XFRM_MSG_DELSA on teardown accepted */
	unsigned long stacked_sa_install_ok;	/* one of the XFRM_MAX_DEPTH v6 stacked null-ESP SAs installed */
	unsigned long stacked_sent_ok;		/* sendto on IPPROTO_RAW v6 for a max-depth stacked-ESP frame returned >0 */
};

#endif /* _TRINITY_STATS_SUBSYS_ESP_CRAFTED_RX_H */
