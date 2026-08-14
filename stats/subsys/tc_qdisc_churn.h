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
	unsigned long qfq_traffic_runs;		/* qfq singleton-aggregate change/enqueue race lane fired */
	unsigned long qfq_traffic_burst_ok;	/* loopback UDP sendto on qfq tree returned >0 */
	unsigned long qfq_traffic_change_ok;	/* RTM_NEWTCLASS change accepted (qfq_change_class ran) */
	unsigned long u32_divisor_create_ok;	/* RTM_NEWTFILTER u32 DIVISOR hnode created */
	unsigned long u32_link_skip_sw_ok;	/* RTM_NEWTFILTER u32 LINK+SKIP_SW hit -EOPNOTSUPP (intentional) */
	unsigned long u32_link_leak_detected;	/* RTM_DELTFILTER hnode returned -EBUSY: refcount leak confirmed */
	unsigned long u32_update_path_step2_bad_errno; /* SKIP_SW update returned neither 0 nor -EOPNOTSUPP (build defect) */
	unsigned long u32_skip_sw_hnode1_arm_done;	/* sticky: hnode1 (errunbind) arm fired */
	unsigned long u32_skip_sw_hnode2_arm_done;	/* sticky: hnode2 (update-path) arm fired */
};

#endif /* _TRINITY_STATS_SUBSYS_TC_QDISC_CHURN_H */
