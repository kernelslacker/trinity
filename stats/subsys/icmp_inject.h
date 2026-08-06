#ifndef _TRINITY_STATS_SUBSYS_ICMP_INJECT_H
#define _TRINITY_STATS_SUBSYS_ICMP_INJECT_H

/*
 * Counters for the crafted-ICMP-error inject primitive
 * (childops/net/crafted-icmp-rx.c).  Two runtime counters plus four
 * selftest-path counters; all updated via __atomic_add_fetch RELAXED.
 */
struct icmp_inject_stats {
	unsigned long errors_injected;	/* icmp_inject_error(): sendto returned >0 */
	unsigned long inject_failed;	/* icmp_inject_error(): sendto failed or init error */
	unsigned long selftest_runs;	/* selftest_icmp_inject() invocations */
	unsigned long selftest_ok;	/* selftest passed (error delivered as expected) */
	unsigned long selftest_fail;	/* selftest failed (unexpected errno or no error) */
	unsigned long init_failed;	/* icmp_inject_init() raw socket open failed */
};

#endif /* _TRINITY_STATS_SUBSYS_ICMP_INJECT_H */
