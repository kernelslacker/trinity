#ifndef _TRINITY_STATS_SUBSYS_IP6ERSPAN_NETNS_MIGRATE_H
#define _TRINITY_STATS_SUBSYS_IP6ERSPAN_NETNS_MIGRATE_H

struct ip6erspan_netns_migrate_stats {
	/* ip6erspan_netns_migrate childop counters */
	unsigned long iters;				/* total ip6erspan_netns_migrate invocations */
	unsigned long eperm;				/* unshare/NEWLINK rejected with EPERM */
	unsigned long unsupported;				/* per-kind ENOENT/EAFNOSUPPORT/EPROTONOSUPPORT/EOPNOTSUPP at create */
	unsigned long link_create_ok;			/* RTM_NEWLINK created the link in the original ns */
	unsigned long netns_migrate_ok;			/* RTM_SETLINK IFLA_NET_NS_FD moved the link to the sibling ns */
	unsigned long changelink_ok;			/* RTM_NEWLINK NLM_F_REPLACE in target ns walked ->changelink */
	/*
	 * ip6erspan_netns_migrate's warn_once_unsupported() latched
	 * ns_unsupported_ip6erspan after an unshare/setns/open or a create-
	 * time ENOENT/EAFNOSUPPORT/EPROTONOSUPPORT/EOPNOTSUPP disabled the
	 * childop for the rest of this child's life.  The original shape
	 * called outputerr from inside the one-shot latch arm, but the
	 * dup2 redirect to /dev/null in init_child swallowed the message,
	 * so a kernel missing the rtnl tunnel machinery this op exercises
	 * looked identical to a healthy one in the operator's log.  Bumping
	 * a shm counter under the same one-shot gate leaves a survivor
	 * signal: one tick per child first-observation, so a high count
	 * fingerprints a host (or build) where the ip6erspan path is
	 * unreachable.
	 */
	unsigned long ip6erspan_unsupported_observed;
	/*
	 * ip6erspan_netns_migrate observed -EOPNOTSUPP from the post-
	 * migration RTM_NEWLINK NLM_F_REPLACE: the kind has no ->changelink
	 * op so create + migrate + teardown still walk but the dev_net-vs-
	 * t->net path under test cannot fire.  The original shape called
	 * outputerr from inside a one-shot ns_unsupported_changelink gate;
	 * the dup2 redirect to /dev/null in init_child lost that
	 * diagnostic.  Bumping a counter under the same one-shot gate keeps
	 * a post-mortem signal -- one tick per child first-observation, so
	 * a non-zero value is the fingerprint of a kernel build whose
	 * rtnl_link_ops lacks the changelink hook for the rolled kind.
	 */
	unsigned long changelink_unsupported_observed;
};

#endif /* _TRINITY_STATS_SUBSYS_IP6ERSPAN_NETNS_MIGRATE_H */
