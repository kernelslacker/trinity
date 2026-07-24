#ifndef _TRINITY_STATS_SUBSYS_DIVERGENCE_SENTINEL_H
#define _TRINITY_STATS_SUBSYS_DIVERGENCE_SENTINEL_H

/*
 * Divergence-sentinel per-field identifiers.  Lives with the counter
 * struct (rather than private to child-sentinel.c) so the per-field
 * anomaly array in struct divergence_sentinel_stats can be sized and
 * indexed by SF__MAX, and so the stats dump can name individual shards
 * via offsetof for periodic / end-of-run reporting.
 *
 * Grouped by source syscall so a post-mortem reader can decode
 * "which syscall, which field" from the single id without a side
 * table.  The gaps in the numbering (5..9 and 14..) are intentional --
 * the post-mortem decoder reads these as raw numeric ids, so leaving
 * the original group bases in place keeps old sentinel entries in
 * already-collected logs unambiguous.
 */
enum sentinel_field {
	SF_UNAME_SYSNAME	= 0,
	SF_UNAME_RELEASE	= 2,
	SF_UNAME_VERSION	= 3,
	SF_UNAME_MACHINE	= 4,

	SF_SYSINFO_TOTALRAM	= 10,
	SF_SYSINFO_TOTALSWAP	= 11,
	SF_SYSINFO_TOTALHIGH	= 12,
	SF_SYSINFO_MEM_UNIT	= 13,

	SF__MAX			= 14,	/* array size for shards; keep > max above */
};

/*
 * periodic_work re-issues a curated set of "should be deterministic
 * across short windows" syscalls (uname, sysinfo, getrlimit/prlimit64
 * RLIMIT_NOFILE, sched_getparam(0)) and compares the result against
 * the previous tick's reading cached in childdata.sentinel_prev.  Any
 * divergence outside the expected drift fields (loads/uptime/freeram
 * et al. are excluded) is the fingerprint of a fuzzed value-result
 * syscall buffer scribbling the cached struct or a kernel-managed
 * datum: a wild write into the cache surfaces as the live re-read
 * disagreeing with what we captured previously, and a wild write into
 * the kernel-managed copy surfaces the same way from the other side.
 * Bumped per diverging field, so a single sample with multi-field
 * corruption contributes more than one to the count -- intentional,
 * to amplify multi-field clobbers above noise from singleton drifts.
 */
struct divergence_sentinel_stats {
	/*
	 * Sharded by enum sentinel_field so an operator can see which
	 * monitored field actually drifted.  pre_crash_ring is only 64
	 * slots wide (overwrite-on-full) and gives the last few ids at
	 * crash time; the per-field counters give the live histogram.
	 * Gaps in the enum (5..9) are present in the array as always-zero
	 * slots -- kept that way so the index matches the on-the-wire
	 * field id in collected logs.
	 *
	 * SF_UNAME_RELEASE and SF_UNAME_MACHINE are routed to
	 * expected_drift below instead of bumping their shard --
	 * personality(PER_LINUX32|UNAME26) legitimately rewrites those
	 * strings every time the fuzzer hits it, so leaving them on the
	 * anomaly histogram would drown out the real wild-write signal.
	 */
	unsigned long anomalies[SF__MAX];

	/*
	 * Counter for divergences in fields that are known to be mutated
	 * by operator-driven syscalls trinity itself fuzzes -- specifically
	 * SF_UNAME_RELEASE and SF_UNAME_MACHINE, which personality()
	 * rewrites every time the bandit fixates on PER_LINUX32 / UNAME26.
	 * Bumped per diverging field, aggregate only (no per-field shard)
	 * -- if a second "expected drift" field is added later this can
	 * be widened.  Mirror of the 2026-05-09 uid_change_logged split:
	 * separating expected mutations from corruption keeps the
	 * headline anomaly array as a real signal rather than a noise
	 * floor.
	 *
	 * SF_SYSINFO_TOTALSWAP intentionally stays on the anomaly array
	 * -- swapon/swapoff bumps it at a far lower rate than
	 * personality() bumps RELEASE/MACHINE, and calling that
	 * "expected" would muddy the meaning of this counter.
	 */
	unsigned long expected_drift;
};

#endif /* _TRINITY_STATS_SUBSYS_DIVERGENCE_SENTINEL_H */
