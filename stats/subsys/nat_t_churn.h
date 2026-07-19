#ifndef _TRINITY_STATS_SUBSYS_NAT_T_CHURN_H
#define _TRINITY_STATS_SUBSYS_NAT_T_CHURN_H

struct nat_t_churn_stats {
	/* nat_t_churn childop counters */
	unsigned long runs;			/* total nat_t_churn invocations */
	unsigned long setup_failed;		/* unshare / NETLINK_XFRM open latched */
	unsigned long sa_added;		/* XFRM_MSG_NEWSA with XFRMA_ENCAP accepted */
	unsigned long sa_deleted;		/* XFRM_MSG_DELSA accepted */
	unsigned long frames_sent;		/* ESP-in-UDP sendto returned >0 */
	/* nat_t_churn IPv6 / UDPv6-encap-ESP error-path branch counters.
	 * Drives the xfrm6 dst error path on UDPv6-encapsulated ESP SAs:
	 * AF_INET6 socket + UDP_ENCAP_ESPINUDP[_NON_IKE] + xfrm v6 SA +
	 * sendto an unreachable 2001:db8::/32 destination so the kernel
	 * walks xfrm_lookup -> esp6_output -> error-return path. */
	/* nat_t_churn IPv6 / UDPv6-encap-ESP error-path branch counters.
	 * Drives the xfrm6 dst error path on UDPv6-encapsulated ESP SAs:
	 * AF_INET6 socket + UDP_ENCAP_ESPINUDP[_NON_IKE] + xfrm v6 SA +
	 * sendto an unreachable 2001:db8::/32 destination so the kernel
	 * walks xfrm_lookup -> esp6_output -> error-return path. */
	unsigned long xfrm6_setup_ok;			/* AF_INET6 NEWSA + UDPv6 socket primed */
	unsigned long xfrm6_setup_fail;			/* NEWSA / sock / setsockopt rejected */
	unsigned long xfrm6_sendto_runs;		/* sendto() to unreachable v6 dest issued */
	unsigned long xfrm6_delsa_races;		/* DELSA accepted while sendto burst inflight */
};

#endif /* _TRINITY_STATS_SUBSYS_NAT_T_CHURN_H */
