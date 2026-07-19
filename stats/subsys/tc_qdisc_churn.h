#ifndef _TRINITY_STATS_SUBSYS_TC_QDISC_CHURN_H
#define _TRINITY_STATS_SUBSYS_TC_QDISC_CHURN_H

struct tc_qdisc_churn_stats {
	/* tc_qdisc_churn childop counters */
	unsigned long runs;		/* total tc_qdisc_churn invocations */
	unsigned long setup_failed;	/* unshare / rtnl_open / dummy latched */
	unsigned long link_create_ok;	/* RTM_NEWLINK type=dummy accepted */
	unsigned long qdisc_create_ok;	/* RTM_NEWQDISC root accepted */
	unsigned long tclass_create_ok;	/* RTM_NEWTCLASS accepted (per class) */
	unsigned long tfilter_create_ok;	/* RTM_NEWTFILTER accepted */
	unsigned long packet_sent_ok;	/* loopback UDP sendto on dummy returned >0 */
	unsigned long qdisc_replace_ok;	/* RTM_NEWQDISC NLM_F_REPLACE accepted (mid-flow swap) */
	unsigned long tfilter_del_ok;	/* RTM_DELTFILTER bulk-del accepted */
	unsigned long qdisc_del_ok;	/* RTM_DELQDISC root accepted */
	unsigned long link_del_ok;	/* RTM_DELLINK on dummy accepted */
	unsigned long peek_stack_runs;		/* deliberate peek-x-peek stack sub-mode fired */
	unsigned long peek_stack_install_ok;	/* parent + child grafted successfully */
	unsigned long peek_stack_install_fail;	/* parent or child install rejected */
	unsigned long peek_stack_burst_ok;	/* loopback UDP sendto on stacked tree returned >0 */
	unsigned long bridge_parent_runs;	/* iter used a bridge slave veth as qdisc parent */
	unsigned long bridge_dellink_race_ok;	/* RTM_DELLINK on bridge slave port accepted (raced flush burst) */
	unsigned long gso_burst_ok;		/* UDP_SEGMENT sendto produced a GSO skb (reaches qdisc_pkt_len_segs_init) */
};

#endif /* _TRINITY_STATS_SUBSYS_TC_QDISC_CHURN_H */
