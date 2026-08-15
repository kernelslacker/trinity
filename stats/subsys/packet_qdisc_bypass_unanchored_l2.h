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
	unsigned long setup_enodev;	/* transient -ENODEV on macsec create (skipped, not latched) */
	unsigned long lane_a_sends;	/* AF_PACKET sendto() calls issued */
	unsigned long lane_b_sends;	/* AF_XDP sendto() kick calls issued */
	unsigned long lane_a_errors;	/* AF_PACKET sendto() returned < 0 */
	unsigned long lane_b_errors;	/* AF_XDP sendto() kick returned non-EAGAIN < 0 */
	unsigned long lane_b_eagain;	/* AF_XDP sendto() returned -EAGAIN (CQ full) */
	unsigned long macsec_sa_installed;      /* TX SA installed via genl before driving lanes */
	unsigned long macsec_sa_install_eperm;  /* TX SA add refused: GENL_ADMIN_PERM / init_user_ns.
					   * By construction this equals the SA-install attempt
					   * count (100% EPERM invariant).  Zero = invariant
					   * broken: macsec genl gained GENL_UNS_ADMIN_PERM, the
					   * call was removed, or the lane was disabled. */
	unsigned long macsec_sa_install_failed; /* TX SA add failed: other non-zero error */
	unsigned long completed_ok;	/* iter reached clean teardown */
	/* if_nlmsg_size() oracle: RTNLGRP_LINK subscriber saw EMSGSIZE from
	 * rtnl_set_sk_err() when creating a macsec link, meaning
	 * rtmsg_ifinfo_build_skb() warned and poisoned subscribed sockets. */
	unsigned long nlmsg_size_undercount_macsec;
	/* Positive control for the oracle above: a successful macsec
	 * RTM_NEWLINK broadcasts a clean RTM_NEWLINK notification that a
	 * live RTNLGRP_LINK subscriber recv()s (n >= 0).  A near-zero count
	 * after completed iters means the subscription is not delivering and
	 * the under-count oracle is decoration (a broken subscription reads
	 * identically to a clean run). */
	unsigned long nlmsg_subscriber_live_macsec;
	/* Subscriber was armed and the macsec link was created, but recv()
	 * returned neither the RTM_NEWLINK broadcast nor an EMSGSIZE poison
	 * (typically EAGAIN): the subscription is not working.  Should be
	 * ~0; a nonzero count means the oracle cannot be trusted. */
	unsigned long nlmsg_subscriber_silent_macsec;
	/* Subscriber socket()/bind() to RTNLGRP_LINK failed, so the oracle
	 * never armed for that iteration.  Should be ~0. */
	unsigned long nlmsg_subscriber_unarmed_macsec;
};

#endif /* _TRINITY_STATS_SUBSYS_PACKET_QDISC_BYPASS_UNANCHORED_L2_H */
