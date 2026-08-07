#ifndef _TRINITY_STATS_SUBSYS_PACKET_QDISC_BYPASS_UNANCHORED_L2_H
#define _TRINITY_STATS_SUBSYS_PACKET_QDISC_BYPASS_UNANCHORED_L2_H

/*
 * Counters for the packet-qdisc-bypass-unanchored-l2 childop
 * (childops/net/packet-qdisc-bypass-unanchored-l2.c).
 *
 * Two lanes probe the same defect class — skb->mac_header left at
 * (u16)~0 on the __dev_direct_xmit() path — from different angles:
 *
 *   Lane A: AF_PACKET with PACKET_QDISC_BYPASS=1 (fixed by c2707480cfbf).
 *           Regression test: skb_reset_mac_header() is now called
 *           unconditionally from packet_parse_headers(), so sends succeed
 *           without OOB reads.
 *
 *   Lane B: AF_XDP in copy mode (XDP_COPY) → xsk_generic_xmit() →
 *           __dev_direct_xmit().  Unfixed twin: xsk_build_skb() never
 *           calls skb_reset_mac_header(), so mac_header stays ~0.
 *           KASAN oracle: slab-out-of-bounds read in macsec_encrypt /
 *           eth_hdr on a CONFIG_MACSEC=m device.
 *
 * All counters updated via __atomic_add_fetch RELAXED.
 */
struct packet_qdisc_bypass_unanchored_l2_stats {
	unsigned long runs;		/* total invocations */
	unsigned long setup_failed;	/* netns/veth/macsec/ring setup error */
	unsigned long lane_a_sends;	/* AF_PACKET sendto() calls issued */
	unsigned long lane_b_sends;	/* AF_XDP sendto() kick calls issued */
	unsigned long lane_a_errors;	/* AF_PACKET sendto() returned < 0 */
	unsigned long lane_b_errors;	/* AF_XDP sendto() kick returned < 0 */
	unsigned long completed_ok;	/* iter reached clean teardown */
};

#endif /* _TRINITY_STATS_SUBSYS_PACKET_QDISC_BYPASS_UNANCHORED_L2_H */
