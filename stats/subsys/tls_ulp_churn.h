#ifndef _TRINITY_STATS_SUBSYS_TLS_ULP_CHURN_H
#define _TRINITY_STATS_SUBSYS_TLS_ULP_CHURN_H

struct tls_ulp_churn_stats {
	/* tls_ulp_churn childop counters */
	unsigned long runs;		/* total tls_ulp_churn invocations */
	unsigned long setup_failed;	/* loopback connect / latch gate failed */
	unsigned long ulp_install_ok;	/* setsockopt(TCP_ULP, "tls") accepted */
	unsigned long tx_install_ok;	/* first TLS_TX setsockopt accepted */
	unsigned long send_ok;		/* send() through tls_sw_sendmsg returned >0 */
	unsigned long splice_ok;		/* splice() into TLS-armed socket returned >0 */
	unsigned long rekey_ok;		/* mid-stream TLS_TX re-install accepted */
	unsigned long recv_ok;		/* recv() through tls_sw_recvmsg returned >0 */
};

#endif /* _TRINITY_STATS_SUBSYS_TLS_ULP_CHURN_H */
