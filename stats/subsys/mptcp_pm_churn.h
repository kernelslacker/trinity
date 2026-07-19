#ifndef _TRINITY_STATS_SUBSYS_MPTCP_PM_CHURN_H
#define _TRINITY_STATS_SUBSYS_MPTCP_PM_CHURN_H

struct mptcp_pm_churn_stats {
	/* mptcp_pm_churn childop counters */
	unsigned long runs;			/* total mptcp_pm_churn invocations */
	unsigned long setup_failed;		/* socket/bind/listen/connect setup failed */
	unsigned long sock_mptcp_ok;		/* IPPROTO_MPTCP server socket created (CONFIG_MPTCP=y) */
	unsigned long addr_added_ok;		/* MPTCP_PM_CMD_ADD_ADDR ack 0 (endpoint installed) */
	unsigned long addr_removed_ok;		/* MPTCP_PM_CMD_DEL_ADDR ack 0 (subflow teardown raced data) */
	unsigned long send_ok;			/* send() through the live MPTCP socket returned >0 */
	unsigned long setsockopt_unsupported;		/* IPPROTO_MPTCP socket() rejected during setsockopt_all_sf recipe */
	unsigned long setsockopt_master_set;		/* setsockopt() on master mptcp socket succeeded */
	unsigned long setsockopt_master_fail;		/* setsockopt() on master mptcp socket failed */
	unsigned long getsockopt_verify_ok;		/* getsockopt() readback matched the value just set */
	unsigned long getsockopt_verify_drift;		/* getsockopt() readback diverged from set value */
	unsigned long sockopt_sweep_runs;		/* sockopt-inheritance sweep sub-mode invocations */
	unsigned long sockopt_set_ok;			/* sweep: setsockopt() on master mptcp socket succeeded */
	unsigned long sockopt_set_failed;		/* sweep: setsockopt() on master mptcp socket failed */
	unsigned long sockopt_subflow_added;		/* sweep: MPTCP_INFO num_subflows bumped after ADD_ADDR */
	unsigned long sockopt_readback_ok;		/* sweep: post-subflow getsockopt() returned the option */
	unsigned long sockopt_inherit_mismatch;		/* sweep: master readback != value set (70ece9d7021c bug-signal) */
	unsigned long sockopt_unsupported_latched;	/* sweep: opt latched out after EOPNOTSUPP/ENOPROTOOPT */
};

#endif /* _TRINITY_STATS_SUBSYS_MPTCP_PM_CHURN_H */
