#ifndef _TRINITY_STATS_SUBSYS_RTNL_VF_BROADCAST_H
#define _TRINITY_STATS_SUBSYS_RTNL_VF_BROADCAST_H

struct rtnl_vf_broadcast_stats {
	/* rtnl_vf_broadcast_getlink childop counters */
	unsigned long runs;		/* total rtnl_vf_broadcast_getlink invocations */
	unsigned long setup_ok;	/* netdevsim+sriov_numvfs+rtnl setup completed */
	unsigned long setup_failed;	/* netdevsim absent / unshare / sriov write failed */
	unsigned long getlink_ok;	/* RTM_GETLINK with RTEXT_FILTER_VF drained a response */
};

#endif /* _TRINITY_STATS_SUBSYS_RTNL_VF_BROADCAST_H */
