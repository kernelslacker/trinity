#ifndef _TRINITY_STATS_SUBSYS_IPV6_NDISC_PROXY_H
#define _TRINITY_STATS_SUBSYS_IPV6_NDISC_PROXY_H

struct ipv6_ndisc_proxy_stats {
	/* ipv6_ndisc_proxy childop counters */
	unsigned long runs;		/* total ipv6_ndisc_proxy invocations */
	unsigned long ns_sent_ok;	/* AF_PACKET NS frame sendto returned >0 */
	unsigned long setup_failed;	/* unshare/veth/addr/proxy setup failed */
	unsigned long proxy_enable_ok;	/* proxy_ndp sysctl flip accepted */
};

#endif /* _TRINITY_STATS_SUBSYS_IPV6_NDISC_PROXY_H */
