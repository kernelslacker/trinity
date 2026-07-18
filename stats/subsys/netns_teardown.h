#ifndef _TRINITY_STATS_SUBSYS_NETNS_TEARDOWN_H
#define _TRINITY_STATS_SUBSYS_NETNS_TEARDOWN_H

struct netns_teardown_stats {
	/* netns_teardown_churn childop counters */
	unsigned long runs;			/* total netns_teardown_churn invocations */
	unsigned long setup_failed;		/* anchor open / fork / unsupported latch fired */
	unsigned long unshare_ok;		/* unshare(CLONE_NEWNET) entered fresh net ns */
	unsigned long socket_pair_ok;		/* in-ns listen+connect TCP pair established on lo */
	unsigned long fork_ok;			/* fork() spawned the in-ns child holding sockets */
	unsigned long setns_ok;			/* parent setns() back to anchor net ns */
	unsigned long kill_ok;			/* SIGKILL delivered to in-ns child (race vs cleanup_net) */
	unsigned long completed_ok;		/* full cycle reached waitpid + close anchor cleanly */
};

#endif /* _TRINITY_STATS_SUBSYS_NETNS_TEARDOWN_H */
