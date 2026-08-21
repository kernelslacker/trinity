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

	/* Device-teardown race arm (xfrm-churn-devteardown.c). */
	unsigned long devteardown_runs;		/* dev-teardown arm entered */
	unsigned long devteardown_v6_runs;	/* of those, AF_INET6 topology (xfrm6_fill_dst on the menu) */
	unsigned long devteardown_setup_failed;	/* dummy / addr / route / SA / policy never came up */
	unsigned long devteardown_armed;	/* topology up, workers about to fork */
	unsigned long devteardown_sent;		/* rotating-destination sendto through the tunnel bundle returned >0 */
	unsigned long devteardown_dellink;	/* RTM_DELLINK of the bundle's egress dummy accepted */

	/* Grammar draw counter: bumped in xfrm_grammar_data_leg() each time
	 * pick_msg_kind() runs, i.e. once per grammar invocation regardless
	 * of which kind is selected.  Used as the denominator for the
	 * dead-arm floor on arm_entered_migrate_state so the floor gates on
	 * how many opportunities the grammar had to draw XMK_MIGRATE_STATE,
	 * not on how many times the xfrm-churn childop ran (an unrelated
	 * execution path that shares this stats struct). Internal-only:
	 * not emitted to JSON. */
	unsigned long msg_kind_draws;            /* grammar pick_msg_kind() calls */

	/* Per-arm entry tally for dead-arm detection.  Bumped at the top
	 * of the XMK_MIGRATE_STATE case in dispatch_msg_kind() before
	 * xfrm_emit_migrate_state() is called, independent of outcome.
	 * When arm_entered_migrate_state == 0 and msg_kind_draws >= floor
	 * the arm was never selected by the probabilistic picker (structural
	 * bug); when arm_entered_migrate_state > 0 and migrate_state_ack_n
	 * == 0 the arm fired but the emitter never produced a kernel ACK
	 * (the class of bug fixed by the msg-type and old_mark corrections). */
	unsigned long arm_entered_migrate_state; /* XMK_MIGRATE_STATE arm entered */
};

#endif /* _TRINITY_STATS_SUBSYS_XFRM_CHURN_H */
