#ifndef _TRINITY_STATS_SUBSYS_FUTEX_PI_REQUEUE_ROLLBACK_H
#define _TRINITY_STATS_SUBSYS_FUTEX_PI_REQUEUE_ROLLBACK_H

/* futex_pi_requeue_rollback childop counters */
struct futex_pi_requeue_rollback_stats {
	unsigned long runs;		/* total invocations */
	unsigned long setup_failed;	/* handshake / spawn shortfall */
	unsigned long requeue_ok;	/* CMP_REQUEUE_PI returned >= 0 */
	unsigned long requeue_failed;	/* CMP_REQUEUE_PI returned < 0 */
};

#endif /* _TRINITY_STATS_SUBSYS_FUTEX_PI_REQUEUE_ROLLBACK_H */
