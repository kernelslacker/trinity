#ifndef _TRINITY_STATS_SUBSYS_SCTP_ASSOC_CHURN_H
#define _TRINITY_STATS_SUBSYS_SCTP_ASSOC_CHURN_H

struct sctp_assoc_churn_stats {
	/* sctp_assoc_churn childop counters */
	unsigned long runs;			/* total sctp_assoc_churn invocations */
	unsigned long setup_failed;		/* socket/bind/listen setup failed (incl. !CONFIG_IP_SCTP) */
	unsigned long bindx_added;		/* SCTP_SOCKOPT_BINDX_ADD accepted (incl. ASCONF emit) */
	unsigned long bindx_removed;		/* SCTP_SOCKOPT_BINDX_REM accepted (incl. ASCONF emit) */
	unsigned long bindx_rejected;		/* bindx ADD/REM rejected (EOPNOTSUPP/EADDRINUSE/EINVAL) */
	unsigned long connect_failed;		/* SCTP_SOCKOPT_CONNECTX failed (non-EINPROGRESS) */
	unsigned long connected;		/* connectx accepted/in-progress */
	unsigned long accepted;		/* server-side accept() returned an assoc fd */
	unsigned long packets_sent;		/* send() through ASCONF / data path returned >0 */
	unsigned long peeled_off;		/* SCTP_SOCKOPT_PEELOFF accepted (assoc detach race) */
	unsigned long peeloff_rejected;	/* peeloff rejected (EINVAL/ENOENT) */
	unsigned long cycles;			/* full cycles reaching teardown */
};

#endif /* _TRINITY_STATS_SUBSYS_SCTP_ASSOC_CHURN_H */
