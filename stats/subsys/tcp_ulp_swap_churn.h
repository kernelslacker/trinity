#ifndef _TRINITY_STATS_SUBSYS_TCP_ULP_SWAP_CHURN_H
#define _TRINITY_STATS_SUBSYS_TCP_ULP_SWAP_CHURN_H

struct tcp_ulp_swap_churn_stats {
	/* tcp_ulp_swap_churn childop counters */
	unsigned long runs;			/* total tcp_ulp_swap_churn invocations */
	unsigned long setup_failed;		/* loopback pair / connect / unsupported latch fired */
	unsigned long install_tls_ok;	/* setsockopt(TCP_ULP, "tls") accepted on connected sock */
	unsigned long tx_install_ok;		/* setsockopt(SOL_TLS, TLS_TX, &cinfo) accepted */
	unsigned long send_ok;		/* tls_sw_sendmsg drove a record onto the wire */
	unsigned long swap_rejected_ok;	/* setsockopt(TCP_ULP, "espintcp"|"smc") rejected post-connect (the bug surface) */
	unsigned long ifname_probe_ok;	/* SIOCGIFNAME / SIOCSIFNAME probe completed without disturbing lo */
	unsigned long uninstall_ok;		/* setsockopt(TCP_ULP, "") uninstall accepted */
	unsigned long reinstall_ok;		/* second setsockopt(TCP_ULP, "tls") accepted (re-init path) */
	unsigned long install_failed;	/* TCP_ULP install non-latch failure (runtime errno bump) */
};

#endif /* _TRINITY_STATS_SUBSYS_TCP_ULP_SWAP_CHURN_H */
