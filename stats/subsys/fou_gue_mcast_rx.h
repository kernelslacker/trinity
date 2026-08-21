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
	unsigned long port_nopartial_ok;	/* FOU_CMD_ADD accepted with FOU_ATTR_REMCSUM_NOPARTIAL set */
	unsigned long gue_flags_uniform;	/* GUE frame kept the uniform-random flags word (validate_gue_flags reject residue) */
	unsigned long gue_priv_emitted;		/* GUE frame carried GUE_FLAG_PRIV with a pflags dword inside Hlen */
	unsigned long gue_remcsum_emitted;	/* GUE frame carried a REMCSUM {start,offset} pair inside Hlen */
	unsigned long gue_remcsum_underflow;	/* of those, offset < start (u16 skb->csum_offset wrap) */
};

#endif /* _TRINITY_STATS_SUBSYS_FOU_GUE_MCAST_RX_H */
