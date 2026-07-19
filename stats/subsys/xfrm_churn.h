#ifndef _TRINITY_STATS_SUBSYS_XFRM_CHURN_H
#define _TRINITY_STATS_SUBSYS_XFRM_CHURN_H

struct xfrm_churn_stats {
	/* xfrm_churn childop counters */
	unsigned long runs;			/* total xfrm_churn invocations */
	unsigned long setup_failed;		/* unshare / NETLINK_XFRM open latched */
	unsigned long sa_added;		/* XFRM_MSG_NEWSA accepted */
	unsigned long tunnel_sa_added;	/* XFRM_MSG_NEWSA accepted with mode=XFRM_MODE_TUNNEL */
	unsigned long iptfs_sa_added;	/* XFRM_MSG_NEWSA accepted with mode=XFRM_MODE_IPTFS */
	unsigned long sa_updated;		/* XFRM_MSG_UPDSA accepted (mid-flow rekey) */
	unsigned long sa_deleted;		/* XFRM_MSG_DELSA accepted */
	unsigned long pol_added;		/* XFRM_MSG_NEWPOLICY accepted */
	unsigned long pol_deleted;		/* XFRM_MSG_DELPOLICY accepted */
	unsigned long esp_sent;		/* loopback UDP send through SP/SA bundle returned >0 */
	unsigned long zc_sent;		/* MSG_ZEROCOPY sendto returned >0 (SKBFL_SHARED_FRAG reached) */
	unsigned long zc_errq_drained;	/* SO_EE_ORIGIN_ZEROCOPY completions drained per burst */
	unsigned long pfkey_send_ok;		/* PF_KEYv2 SADB_FLUSH send returned >0 */
	unsigned long burn_runs;		/* burn-this-netns branch attempted */
	unsigned long burn_throttled;		/* burn-this-netns skipped: MAX_CONCURRENT_NEWNET cap reached */
	unsigned long burn_completed;		/* burn-this-netns reached the readers + larval insert */
};

#endif /* _TRINITY_STATS_SUBSYS_XFRM_CHURN_H */
