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

struct divergence_sentinel_stats {
	unsigned long anomalies[SF__MAX];
	unsigned long expected_drift;
};

#endif /* _TRINITY_STATS_SUBSYS_DIVERGENCE_SENTINEL_H */
