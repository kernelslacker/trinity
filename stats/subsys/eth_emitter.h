#ifndef _TRINITY_STATS_SUBSYS_ETH_EMITTER_H
#define _TRINITY_STATS_SUBSYS_ETH_EMITTER_H

/* eth_emitter childop counters: AF_PACKET/SOCK_RAW L2 emitter that
 * crafts one frame per call from one of NR_TEMPLATES template
 * families (ARP, IPv4 frag-zero, IPv6 NA, VLAN Q-in-Q, malformed
 * EtherType) and sendto()s it to loopback.  per_tmpl[] indexes
 * template successes so the operator can confirm coverage stays
 * spread across all five families rather than collapsing on one. */
struct eth_emitter_stats {
	unsigned long runs;			/* total eth_emitter invocations */
	unsigned long setup_failed;		/* socket(AF_PACKET) or bind() failed (EPERM/CAP_NET_RAW absent) */
	unsigned long short_frame;		/* template returned a length out of range; frame skipped */
	unsigned long sends_ok;			/* sendto returned >0 */
	unsigned long sends_failed;		/* sendto returned <=0 (queue full / EPERM / etc.) */
	unsigned long per_tmpl[5];		/* per-template successful sends (NR_TEMPLATES in childops/net/eth-emitter.c) */
};

#endif /* _TRINITY_STATS_SUBSYS_ETH_EMITTER_H */
