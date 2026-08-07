#ifndef _TRINITY_STATS_SUBSYS_FNHE_PMTU_MTU_RACE_H
#define _TRINITY_STATS_SUBSYS_FNHE_PMTU_MTU_RACE_H

/*
 * Counters for the fnhe-pmtu-mtu-race childop
 * (childops/net/fnhe-pmtu-mtu-race.c).
 *
 * The childop populates the IPv4 per-nexthop PMTU exception (fnhe) table
 * by injecting crafted ICMP frag-needed packets, then concurrently flaps
 * the veth MTU to race fib_nhc_update_mtu() against fnhe_remove_oldest().
 * All counters are updated via __atomic_add_fetch RELAXED.
 */
struct fnhe_pmtu_mtu_race_stats {
	unsigned long runs;			/* total invocations */
	unsigned long setup_failed;		/* netns/veth/addr/route setup error */
	unsigned long injections_sent;		/* ICMP inject sendto() succeeded */
	unsigned long exceptions_installed;	/* RTM_GETROUTE confirmed fnhe pmtu=1280 */
	unsigned long inject_failed;		/* ICMP inject sendto failed */
	unsigned long evictions_observed;	/* bucket overflow detected (estimated) */
	unsigned long mtu_flaps;		/* SIOCSIFMTU ioctl calls issued */
	unsigned long negative_ctrl_runs;	/* runs with no injection (empty table) */
	unsigned long completed_ok;		/* iter reached clean teardown */
};

#endif /* _TRINITY_STATS_SUBSYS_FNHE_PMTU_MTU_RACE_H */
