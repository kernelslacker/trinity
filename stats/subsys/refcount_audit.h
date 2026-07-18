#ifndef _TRINITY_STATS_SUBSYS_REFCOUNT_AUDIT_H
#define _TRINITY_STATS_SUBSYS_REFCOUNT_AUDIT_H

struct refcount_audit_stats {
	/* refcount_auditor childop counters */
	unsigned long runs;
	unsigned long fd_anomalies;
	unsigned long mmap_anomalies;
	unsigned long sock_anomalies;
};

#endif /* _TRINITY_STATS_SUBSYS_REFCOUNT_AUDIT_H */
