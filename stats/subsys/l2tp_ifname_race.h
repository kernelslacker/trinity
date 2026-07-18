#ifndef _TRINITY_STATS_SUBSYS_L2TP_IFNAME_RACE_H
#define _TRINITY_STATS_SUBSYS_L2TP_IFNAME_RACE_H

struct l2tp_ifname_race_stats {
	/* l2tp_ifname_race childop counters */
	unsigned long runs;			/* total l2tp_ifname_race invocations */
	unsigned long setup_failed;		/* genl family probe / netns unshare / parent ctx latch fired */
	unsigned long iter;			/* outer-loop iterations entered */
	unsigned long tunnel_ok;		/* L2TP_CMD_TUNNEL_CREATE accepted by kernel */
	unsigned long tunnel_fail;		/* L2TP_CMD_TUNNEL_CREATE rejected */
	unsigned long fork_failed;		/* fork() of a creator/racer worker failed */
	unsigned long spawn_pair_ok;		/* both creator + racer spawned for this round */
	unsigned long sibling_reaped_ok;	/* worker exited normally and was reaped */
	unsigned long sibling_crashed;		/* worker killed by signal (SEGV/BUS/KILL) -- forensic hint */
};

#endif /* _TRINITY_STATS_SUBSYS_L2TP_IFNAME_RACE_H */
