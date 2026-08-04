#ifndef _TRINITY_STATS_SUBSYS_RPL_CLONE_FIDELITY_H
#define _TRINITY_STATS_SUBSYS_RPL_CLONE_FIDELITY_H

struct rpl_clone_fidelity_stats {
	/* ipv6_rpl_clone_fidelity childop counters.  Bumped when the
	 * oracle observes that the raw6 SOCK_RAW clone or the AF_PACKET
	 * full-frame observer sees mutated SRH / IPv6 header bytes vs the
	 * transmitted frame -- indicating ipv6_rpl_srh_rcv() modified
	 * the shared data of an skb_clone() that was delivered to the raw
	 * socket before the routing handler ran.  The op's outputerr()
	 * line carries the first-divergence offset and hex windows for
	 * triage; this counter is the durable headless signal. */
	unsigned long srh_mutated;
	/* Frames where the AF_PACKET full-frame observer independently
	 * confirmed mutation in the IPv6 header (daddr swap visible). */
	unsigned long daddr_mutated;
};

#endif /* _TRINITY_STATS_SUBSYS_RPL_CLONE_FIDELITY_H */
