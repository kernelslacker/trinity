#ifndef _TRINITY_STATS_SUBSYS_CT_EXPECT_REALLOC_H
#define _TRINITY_STATS_SUBSYS_CT_EXPECT_REALLOC_H

struct ct_expect_realloc_stats {
	unsigned long runs;		/* total ct_expect_realloc invocations */
	unsigned long ns_setup_failed;	/* userns/netns bring-up failed transiently */
	unsigned long ns_unsupported;	/* userns policy refused (latched) */
	unsigned long ct_setup_failed;	/* nfnl socket open or CTNETLINK probe failed */
	unsigned long helper_missing;	/* no in-kernel helper available (all names rejected) */
	unsigned long master_ok;	/* CT_NEW + CTA_HELP ack 0 (helper ext attached) */
	unsigned long expect_ok;	/* EXP_NEW ack 0 (expectation inserted onto help->expectations) */
	unsigned long realloc_ok;	/* CT_NEW NLM_F_REPLACE + CTA_LABELS ack 0 (ext realloc trigger fired) */
	unsigned long unlink_ok;	/* EXP_DELETE ack 0 (unlink wrote through hlist backpointer) */
	unsigned long full_cycle;	/* all four steps landed cleanly on one master */
};

#endif /* _TRINITY_STATS_SUBSYS_CT_EXPECT_REALLOC_H */
