#ifndef _TRINITY_STATS_SUBSYS_GENETLINK_FUZZER_H
#define _TRINITY_STATS_SUBSYS_GENETLINK_FUZZER_H

struct genetlink_fuzzer_stats {
	/* genetlink_fuzzer childop counters */
	unsigned long families_discovered;	/* cumulative across children */
	unsigned long msgs_sent;		/* successful send() to a family */
	unsigned long eperm;			/* family rejected with EPERM/EACCES */
	/* NLMSG_ERROR entry whose nlmsg_seq did not match the seq the
	 * caller passed to nl_send_drain_errors() -- a stale ack left
	 * in the socket queue by an earlier request, possibly from a
	 * different family.  Counted so the queue-hygiene rate stays
	 * visible; the drop suppresses the on_err callback so a stale
	 * -EPERM/-EACCES cannot latch the wrong family's needs_priv. */
	unsigned long stale_seq_drops;
	/* CTRL_CMD_GETFAMILY/NLM_F_DUMP completed cleanly (NLMSG_DONE)
	 * but produced zero usable family entries.  Bumped at the
	 * empty-catalog bail in the persistent fuzz child so a genuine
	 * "kernel has no registered genetlink families" outcome is
	 * counted explicitly instead of vanishing into a silent return
	 * that only surfaces as derived setup_fail.  Separable from a
	 * transport-side failure (discovery_io_err) and a
	 * controller-rejection (discovery_nlerr). */
	unsigned long missing_producer;
	/* CTRL_CMD_GETFAMILY dump failed with a local I/O error: short
	 * recv, sendmsg failure, recv timeout, or a malformed reply
	 * stream with no DONE/ERROR seen.  Bumped instead of
	 * missing_producer when the empty-catalog bail is caused by
	 * transport rather than an empty kernel registry. */
	unsigned long discovery_io_err;
	/* CTRL_CMD_GETFAMILY dump terminated with a mid-dump
	 * NLMSG_ERROR (negated errno from the controller family).
	 * Bumped instead of missing_producer for that case so a
	 * kernel-side rejection is distinguishable from both a
	 * transport failure and a genuinely empty registry. */
	unsigned long discovery_nlerr;
	/* Successful CTRL_CMD_GETFAMILY dumps that produced a
	 * non-empty catalog.  Bumped once per genetlink_fuzzer()
	 * invocation just before the grandchild fork.  Distinct from
	 * families_discovered, which sums cat->count across cycles
	 * (entries).  With cycles + entries we can tell a healthy
	 * 50-entry dump repeated N times from a degraded 2-entry dump
	 * repeated many more times, and we can compare cycles against
	 * msgs_sent to localise a discovery-to-send stall
	 * (setup_accepted bumps alongside this counter, so cycles ==
	 * setup_accepted on the hot path). */
	unsigned long discovery_cycles;
	/* userns_run_in_ns(CLONE_NEWNET, genetlink_fuzzer_in_ns, ...)
	 * returned < 0 for any reason (EPERM policy latch, EAGAIN
	 * transient fork/id-map/target-unshare failure, waitpid
	 * failure).  Bumped alongside the appropriate
	 * userns_bootstrap_* counter so we can attribute a
	 * "setup_accepted grows but msgs_sent stays zero" pattern to
	 * userns/netns bootstrap vs. the in-ns nl_open vs. the send
	 * itself without cross-referencing every other userns caller. */
	unsigned long userns_run_fail;
	/* Grandchild-side nl_open(NETLINK_GENERIC) in the fresh
	 * user+net namespace returned < 0.  The pre-existing
	 * outputerr line covers per-event debugging; this counter
	 * gives the rate.  When this is the dominant miss the fix is
	 * in the ns-bootstrap path (missing loopback, missing family
	 * registration, LSM refusal) rather than in the send path. */
	unsigned long in_ns_open_fail;
	/* Grandchild-side nl_send_drain_errors() returned < 0
	 * (sendmsg failure, recv returned non-EAGAIN error).
	 * Previously silent — send_fuzzed_msg() bailed without
	 * bumping msgs_sent and without accounting the miss, so a
	 * consistently-failing sendmsg looked identical to a healthy
	 * op that never picked this family.  When this is the
	 * dominant miss the fault is in the send-path envelope, not
	 * in ns bootstrap. */
	unsigned long send_drain_fail;
};

#endif /* _TRINITY_STATS_SUBSYS_GENETLINK_FUZZER_H */
