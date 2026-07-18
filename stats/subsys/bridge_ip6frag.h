#ifndef _TRINITY_STATS_SUBSYS_BRIDGE_IP6FRAG_H
#define _TRINITY_STATS_SUBSYS_BRIDGE_IP6FRAG_H

struct bridge_ip6frag_stats {
	/* bridge_ip6frag_refrag childop counters */
	unsigned long runs;		/* total bridge_ip6frag_refrag invocations */
	unsigned long pairs_sent;	/* two-fragment IPv6 datagram pairs attempted */
	unsigned long frames_sent;	/* individual IPv6 fragment frames sendto() >0 */
};

#endif /* _TRINITY_STATS_SUBSYS_BRIDGE_IP6FRAG_H */
