#ifndef _TRINITY_STATS_SUBSYS_VRF_FIB_CHURN_H
#define _TRINITY_STATS_SUBSYS_VRF_FIB_CHURN_H

struct vrf_fib_churn_stats {
	/* vrf_fib_churn childop counters */
	unsigned long runs;		/* total vrf_fib_churn invocations */
	unsigned long setup_failed;	/* unshare(CLONE_NEWNET) or rtnl socket failed */
	unsigned long link_ok;		/* RTM_NEWLINK kind=vrf accepted */
	unsigned long addr_ok;		/* RTM_NEWADDR on the vrf dev accepted */
	unsigned long up_ok;		/* RTM_NEWLINK setlink IFF_UP accepted */
	unsigned long rule_added;		/* RTM_NEWRULE FRA_TABLE accepted */
	unsigned long bound;		/* SO_BINDTODEVICE on the vrf accepted */
	unsigned long sendto_ok;		/* sendto() through bound vrf returned >=0 */
	unsigned long rule2_added;	/* mid-traffic higher-prio RTM_NEWRULE accepted */
	unsigned long rule_removed;	/* RTM_DELRULE for the bound rule accepted */
	unsigned long link_removed;	/* RTM_DELLINK vrf accepted (full cycle reached teardown) */
};

#endif /* _TRINITY_STATS_SUBSYS_VRF_FIB_CHURN_H */
