#ifndef _TRINITY_STATS_SUBSYS_ESPINTCP_COALESCE_H
#define _TRINITY_STATS_SUBSYS_ESPINTCP_COALESCE_H

struct espintcp_coalesce_stats {
	/* espintcp_coalesce_churn childop counters */
	unsigned long runs;			/* total espintcp_coalesce_churn invocations */
	unsigned long setup_failed;		/* userns_run_in_ns / loopback pair setup failed (incl. kind-latched or !CONFIG_INET_ESPINTCP) */
	unsigned long ulp_install_ok;		/* setsockopt(TCP_ULP, "espintcp") accepted on connected sock */
	unsigned long ulp_install_failed;	/* setsockopt(TCP_ULP, "espintcp") rejected (any errno) */
	unsigned long send_ok;		/* crafted length-prefixed frame send >0 */
	unsigned long keepalive_ok;		/* zero-length non-ESP marker keepalive frame emitted */
};

#endif /* _TRINITY_STATS_SUBSYS_ESPINTCP_COALESCE_H */
