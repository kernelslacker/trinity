#ifndef _TRINITY_STATS_SUBSYS_TLS_ROTATE_H
#define _TRINITY_STATS_SUBSYS_TLS_ROTATE_H

struct tls_rotate_stats {
	/* tls_rotate childop counters */
	unsigned long runs;			/* total tls_rotate invocations */
	unsigned long setup_failed;		/* loopback TCP pair setup failed */
	unsigned long ulp_failed;		/* setsockopt(TCP_ULP, "tls") failed (no CONFIG_TLS) */
	unsigned long ulp_asymmetric;	/* server-side TCP_ULP install failed; RX path skipped */
	unsigned long installs;		/* successful initial TLS_TX install */
	unsigned long rekeys_ok;		/* rekey TLS_TX install accepted */
	unsigned long rekeys_rejected;	/* rekey TLS_TX install rejected (EBUSY etc) */
};

#endif /* _TRINITY_STATS_SUBSYS_TLS_ROTATE_H */
