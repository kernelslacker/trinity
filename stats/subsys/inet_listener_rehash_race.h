#ifndef _TRINITY_STATS_SUBSYS_INET_LISTENER_REHASH_RACE_H
#define _TRINITY_STATS_SUBSYS_INET_LISTENER_REHASH_RACE_H

struct inet_listener_rehash_race_stats {
	/* inet_listener_rehash_race childop counters */
	unsigned long runs;			/* total invocations */
	unsigned long setup_failed;		/* AF_INET socket() probe / latched */
	unsigned long iter;			/* outer race rounds started */
	unsigned long fork_failed;		/* fork() failed for a worker */
	unsigned long spawn_quad_ok;		/* all four race workers spawned */
	unsigned long twseed_listener_ok;	/* twseed acceptor listen() ok */
	unsigned long twseed_ok;		/* twseed client connect() egress */
	unsigned long churn_v4_cycles;		/* v4 listener bind+listen+close cycles */
	unsigned long churn_v6_cycles;		/* v6 listener bind+listen+close cycles */
	unsigned long syn_sent;			/* connect() SYNs driven at target port */
	unsigned long rehash_cycles;		/* bind+connect rehash-driver cycles */
	unsigned long sibling_crashed;		/* worker exited on signal (bug surface) */
	unsigned long sibling_reaped_ok;	/* worker exited normally */
	unsigned long completed_ok;		/* invocations reaching teardown */
	/* IPV6_ADDRFORM sequential arm */
	unsigned long addrform_returned_zero;	/* setsockopt(IPV6_ADDRFORM,PF_INET)==0 */
	unsigned long addrform_child_accepted;	/* accept() on addrform'd listener ok */
	unsigned long addrform_setup_failed;	/* goto out before step 3 (setup failure) */
};

#endif /* _TRINITY_STATS_SUBSYS_INET_LISTENER_REHASH_RACE_H */
