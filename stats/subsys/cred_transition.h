#ifndef _TRINITY_STATS_SUBSYS_CRED_TRANSITION_H
#define _TRINITY_STATS_SUBSYS_CRED_TRANSITION_H

struct cred_transition_stats {
	/* cred_transition_churn childop counters */
	unsigned long runs;			/* total cred_transition_churn invocations */
	unsigned long setup_failed;		/* userns_run_in_ns / capget refused; unsupported latch fired */
	unsigned long capset_ok;		/* capset() re-installed a churned effective subset */
	unsigned long capset_failed;		/* capset() rejected the churned mask (EPERM/EINVAL) */
	unsigned long op_ok;			/* post-capset permission-sensitive op succeeded */
	unsigned long op_failed;		/* post-capset permission-sensitive op rejected (EPERM/EACCES/EINVAL) */
	unsigned long keyctl_ok;		/* session-keyring keyctl churn call succeeded */
	unsigned long keyctl_failed;		/* session-keyring keyctl churn call rejected */
};

#endif /* _TRINITY_STATS_SUBSYS_CRED_TRANSITION_H */
