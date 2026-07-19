#ifndef _TRINITY_STATS_SUBSYS_BRIDGE_IP6_REFRAG_FRAGGAP_H
#define _TRINITY_STATS_SUBSYS_BRIDGE_IP6_REFRAG_FRAGGAP_H

struct bridge_ip6_refrag_fraggap_stats {
	/* bridge_ip6_refrag_fraggap childop counters */
	unsigned long runs;		/* total bridge_ip6_refrag_fraggap invocations */
	unsigned long brnf_enabled;	/* bridge-nf-call-ip6tables sysctl write accepted */
	unsigned long bursts;		/* per-iter frag-pair emission bursts inside the netns */
	unsigned long frags_sent;	/* individual fragment frames sendto returned >0 */
};

#endif /* _TRINITY_STATS_SUBSYS_BRIDGE_IP6_REFRAG_FRAGGAP_H */
