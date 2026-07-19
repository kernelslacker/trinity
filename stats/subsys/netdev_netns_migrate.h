#ifndef _TRINITY_STATS_SUBSYS_NETDEV_NETNS_MIGRATE_H
#define _TRINITY_STATS_SUBSYS_NETDEV_NETNS_MIGRATE_H

struct netdev_netns_migrate_stats {
	/* netdev_netns_migrate childop counters */
	unsigned long iters;				/* total netdev_netns_migrate invocations */
	unsigned long eperm;				/* helper -EPERM or RTM_NEWLINK EPERM */
	unsigned long unsupported;				/* per-kind ENOENT/EAFNOSUPPORT/EPROTONOSUPPORT/EOPNOTSUPP at create */
	unsigned long pin_sock_ok;				/* AF_INET SOCK_DGRAM pinned in source ns */
	unsigned long link_create_ok;			/* RTM_NEWLINK created the netdev in the source ns */
	unsigned long migrate_ok;				/* RTM_SETLINK IFLA_NET_NS_FD moved the netdev to the sibling ns */
	unsigned long migrate_rejected;			/* setlink IFLA_NET_NS_FD returned EOPNOTSUPP/EINVAL */
	unsigned long up_ok;				/* RTM_SETLINK IFF_UP in target ns succeeded */
	unsigned long addr_ok;				/* RTM_NEWADDR IPv4 in target ns succeeded */
	/*
	 * netdev_netns_migrate latched itself off after helper -EPERM or a
	 * setup-side EPERM/setns/unshare failure.  One-shot per child
	 * first-observation, mirroring the ip6erspan_netns_migrate counter
	 * above -- a non-zero value fingerprints a host where the
	 * unprivileged userns + private-netns setup this childop relies on
	 * is unavailable (user.max_user_namespaces=0 /
	 * kernel.unprivileged_userns_clone=0 / capability restriction).
	 */
	unsigned long unsupported_observed;
	/*
	 * netdev_netns_migrate observed -EOPNOTSUPP from the post-
	 * migration RTM_SETLINK IFF_UP: the kernel refused to bring the
	 * migrated device up in the target ns for the rolled kind, so
	 * create + migrate + teardown still walk but the post-migration
	 * drive step cannot fire.  One-shot per child first-observation;
	 * a non-zero value is the fingerprint of a kernel build where one
	 * of the rolled kinds cannot be brought up in an unprivileged
	 * userns-owned netns.
	 */
	unsigned long drive_unsupported_observed;
};

#endif /* _TRINITY_STATS_SUBSYS_NETDEV_NETNS_MIGRATE_H */
