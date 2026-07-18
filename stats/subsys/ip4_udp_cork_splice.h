#ifndef _TRINITY_STATS_SUBSYS_IP4_UDP_CORK_SPLICE_H
#define _TRINITY_STATS_SUBSYS_IP4_UDP_CORK_SPLICE_H

struct ip4_udp_cork_splice_stats {
	/* ip4_udp_cork_splice childop counters */
	unsigned long runs;			/* total ip4_udp_cork_splice invocations */
	unsigned long setup_failed;		/* userns_run_in_ns / rtnl / lo setup failed */
	unsigned long mtu_set;		/* lo MTU netlink accepted */
	unsigned long p1_ok;		/* corked MTU-filling sendmsg returned P1 bytes */
	unsigned long p1_rejected;		/* corked sendmsg returned short / -1 (splice path refused) */
	unsigned long p2_ok;		/* flushing tail sendmsg returned >=0 (trigger burst emitted) */
};

#endif /* _TRINITY_STATS_SUBSYS_IP4_UDP_CORK_SPLICE_H */
