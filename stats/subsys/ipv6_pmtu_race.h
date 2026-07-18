#ifndef _TRINITY_STATS_SUBSYS_IPV6_PMTU_RACE_H
#define _TRINITY_STATS_SUBSYS_IPV6_PMTU_RACE_H

struct ipv6_pmtu_race_stats {
	/* ipv6_pmtu_teardown_race childop counters */
	unsigned long runs;			/* total ipv6_pmtu_teardown_race invocations */
	unsigned long setup_failed;		/* probe / anchor / unshare / worker fork failed */
	unsigned long ptb_sent_ok;		/* sendto(ICMPV6_PKT_TOOBIG) returned >=0 */
	unsigned long dellink_ok;		/* RTM_DELLINK ack 0 from worker B */
	unsigned long completed_ok;		/* iter_one reached setns-back + close cleanly */
};

#endif /* _TRINITY_STATS_SUBSYS_IPV6_PMTU_RACE_H */
