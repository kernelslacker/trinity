#ifndef _TRINITY_STATS_SUBSYS_NF_CONNTRACK_HELPER_CHURN_H
#define _TRINITY_STATS_SUBSYS_NF_CONNTRACK_HELPER_CHURN_H

struct nf_conntrack_helper_churn_stats {
	/* nf_conntrack_helper_churn childop counters */
	unsigned long runs;		/* total nf_conntrack_helper_churn invocations */
	unsigned long setup_failed;	/* nfnl socket open / CTNETLINK probe failed */
	unsigned long no_helper;	/* runtime helper-mask empty (no helpers loaded) */
	unsigned long attach_ok;	/* CT_NEW + CTA_HELP ack 0 or EEXIST (attach path ran) */
	unsigned long attach_fail;	/* CT_NEW + CTA_HELP rejected (validation ran) */
	unsigned long exp_ok;		/* EXP_NEW ack 0 (expectation registered) */
	unsigned long packet_sent;	/* loopback drive packet emitted (helper ->help() path) */
	unsigned long delete_ok;	/* CT_DELETE ack 0 (race vs helper expectation walk) */
	unsigned long zone_swap;	/* SO_MARK-driven zone-swap drive packet emitted */
	unsigned long detach_ok;	/* CT_NEW NLM_F_REPLACE w/o CTA_HELP ack 0 (detach race) */
};

#endif /* _TRINITY_STATS_SUBSYS_NF_CONNTRACK_HELPER_CHURN_H */
