#ifndef _TRINITY_STATS_SUBSYS_MSG_ZEROCOPY_CHURN_H
#define _TRINITY_STATS_SUBSYS_MSG_ZEROCOPY_CHURN_H

struct msg_zerocopy_churn_stats {
	/* msg_zerocopy_churn childop counters */
	unsigned long runs;			/* total msg_zerocopy_churn invocations */
	unsigned long setup_failed;		/* loopback pair / SO_ZEROCOPY install / mmap / unsupported latch fired */
	unsigned long sends_ok;		/* send(MSG_ZEROCOPY) returned >=0 (notification will queue) */
	unsigned long sends_efault;		/* send(MSG_ZEROCOPY) returned EFAULT (page-pin failure path reached) */
	unsigned long sends_eagain;		/* send(MSG_ZEROCOPY) returned EAGAIN/EWOULDBLOCK (retry-cap saturated) */
	unsigned long errqueue_drained;	/* recvmsg(MSG_ERRQUEUE) drained at least one notif (sock_extended_err shape validated) */
	unsigned long errqueue_empty;	/* recvmsg(MSG_ERRQUEUE) returned EAGAIN on first attempt (no notifs yet) */
	unsigned long munmap_ok;		/* munmap of backing pages succeeded mid-flight (skb may still pin them) */
	unsigned long send_after_munmap_caught;	/* send(MSG_ZEROCOPY) after munmap returned EFAULT (rollback path reached) */
	unsigned long sndzc_disable_ok;	/* setsockopt(SO_ZEROCOPY, 0) accepted with notifs possibly pending */
};

#endif /* _TRINITY_STATS_SUBSYS_MSG_ZEROCOPY_CHURN_H */
