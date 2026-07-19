#ifndef _TRINITY_STATS_SUBSYS_PFKEY_SPD_WALK_H
#define _TRINITY_STATS_SUBSYS_PFKEY_SPD_WALK_H

struct pfkey_spd_walk_stats {
	/* pfkey_spd_walk childop counters */
	unsigned long runs;			/* total pfkey_spd_walk invocations */
	unsigned long setup_failed;		/* AF_KEY probe or netns unshare latch fired */
	unsigned long iter;			/* outer-loop iterations entered */
	unsigned long fork_failed;		/* fork() of a walker/racer worker failed */
	unsigned long spawn_pair_ok;		/* both walker + racer spawned for this round */
	unsigned long sibling_reaped_ok;		/* worker exited normally and was reaped */
	unsigned long sibling_crashed;		/* worker killed by signal (SEGV/BUS/KILL) -- forensic hint */
	/* SPDGET resolution counters.  The racer alternates SADB_X_SPDDUMP
	 * with SADB_X_SPDGET against a small set of policy ids; the SPDDUMP
	 * arm always finds something to walk, but kernel-assigned policy
	 * ids are sparse and the SPDGET arm typically never lands on a live
	 * id.  pfkey_spdget_resolved bumps when an inbound SPDGET reply
	 * carries sadb_msg_errno == 0 (the kernel resolved the id);
	 * pfkey_spdget_missed bumps when the reply carries a nonzero errno
	 * (typically -ESRCH).  A 0% resolved rate over a long run flags
	 * that the SPDGET arm is contributing no real coverage and the id
	 * pool needs to be steered toward live ids -- counter-only here;
	 * the sparse-id root cause is tracked separately. */
	unsigned long spdget_resolved;
	unsigned long spdget_missed;
};

#endif /* _TRINITY_STATS_SUBSYS_PFKEY_SPD_WALK_H */
