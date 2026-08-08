#ifndef _TRINITY_STATS_SUBSYS_IPCNS_UCOUNT_EXHAUSTION_H
#define _TRINITY_STATS_SUBSYS_IPCNS_UCOUNT_EXHAUSTION_H

struct ipcns_ucount_exhaustion_stats {
	/* Total ipcns_ucount_exhaustion invocations that completed all lanes. */
	unsigned long runs;
	/* Inner child died by signal (unexpected crash inside userns). */
	unsigned long inner_crashed;
	/* Writing IPCNS_LIMIT to /proc/sys/user/max_ipc_namespaces failed. */
	unsigned long limit_install_failed;
	/*
	 * Outer waitpid for the inner fork child timed out: the child
	 * is stuck in D-state (e.g. inside synchronize_rcu() triggered
	 * by flush_work(&free_ipc_work)).  We stop waiting rather than
	 * blocking the child slot indefinitely.
	 */
	unsigned long inner_timeout;
};

#endif /* _TRINITY_STATS_SUBSYS_IPCNS_UCOUNT_EXHAUSTION_H */
