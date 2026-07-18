#ifndef _TRINITY_STATS_SUBSYS_IP_GRE_CHURN_H
#define _TRINITY_STATS_SUBSYS_IP_GRE_CHURN_H

struct ip_gre_churn_stats {
	/* ip_gre_churn childop counters */
	unsigned long runs;		/* total ip_gre_churn invocations */
	unsigned long setup_failed;	/* unshare(CLONE_NEWNET) / rtnl_open / kind latched */
	unsigned long link_create_ok;	/* RTM_NEWLINK type=gretap accepted */
	unsigned long link_up_ok;		/* RTM_NEWLINK setlink IFF_UP accepted */
	unsigned long packet_sent_ok;	/* sendto on IPPROTO_RAW returned >0 */
	unsigned long link_del_ok;		/* RTM_DELLINK accepted */
};

#endif /* _TRINITY_STATS_SUBSYS_IP_GRE_CHURN_H */
