#ifndef _TRINITY_STATS_SUBSYS_ORACLE_H
#define _TRINITY_STATS_SUBSYS_ORACLE_H

/*
 * Post-syscall oracle anomaly counters.  Each member is bumped when a
 * post handler (or the sampled capdrop invariant fired from
 * periodic_work()) detects that the kernel returned a shape the
 * corresponding oracle deems anomalous -- unexpected value, structural
 * violation, or invariant broken -- for the syscall whose name prefixes
 * the counter.  Grouped as Group B ("per-syscall, rare-condition") in
 * struct stats_s: on the hot dispatch path but only bumped on the rare
 * anomalous outcome, so cacheline-isolated from the true hot Group A
 * counters via the parent struct's aligned(64) on the oracle member.
 *
 * The counter identifiers keep the full <syscall>_oracle_anomalies form
 * (rather than being stripped to a bare <syscall>_anomalies) so grep and
 * blame stay unambiguous across the syscall trees where the bump sites
 * live -- fd_oracle_anomalies is the fd oracle, capdrop_oracle_anomalies
 * is the capdrop oracle, and so on.  The JSON schema still emits each
 * row as "<syscall>_anomalies" (the "oracle_" infix is implicit in the
 * enclosing category key), pinned via STAT_FIELD_JSON_SUB in
 * stats/subsys/oracle.c.
 */
struct oracle_stats {
	unsigned long fd_oracle_anomalies;
	unsigned long mmap_oracle_anomalies;
	unsigned long cred_oracle_anomalies;
	unsigned long sched_oracle_anomalies;
	unsigned long uid_oracle_anomalies;
	unsigned long gid_oracle_anomalies;
	unsigned long setgroups_oracle_anomalies;
	unsigned long getegid_oracle_anomalies;
	unsigned long getuid_oracle_anomalies;
	unsigned long getgid_oracle_anomalies;
	unsigned long getppid_oracle_anomalies;
	unsigned long getcwd_oracle_anomalies;
	unsigned long getpid_oracle_anomalies;
	unsigned long getpgid_oracle_anomalies;
	unsigned long getpgrp_oracle_anomalies;
	unsigned long geteuid_oracle_anomalies;
	unsigned long getsid_oracle_anomalies;
	unsigned long gettid_oracle_anomalies;
	unsigned long setsid_oracle_anomalies;
	unsigned long setpgid_oracle_anomalies;
	unsigned long sched_getscheduler_oracle_anomalies;
	unsigned long getgroups_oracle_anomalies;
	unsigned long getresuid_oracle_anomalies;
	unsigned long getresgid_oracle_anomalies;
	unsigned long umask_oracle_anomalies;
	unsigned long sched_get_priority_max_oracle_anomalies;
	unsigned long sched_get_priority_min_oracle_anomalies;
	unsigned long sched_yield_oracle_anomalies;
	unsigned long getpagesize_oracle_anomalies;
	unsigned long time_oracle_anomalies;
	unsigned long gettimeofday_oracle_anomalies;
	unsigned long newuname_oracle_anomalies;
	unsigned long rt_sigpending_oracle_anomalies;
	unsigned long sched_getaffinity_oracle_anomalies;
	unsigned long rt_sigprocmask_oracle_anomalies;
	unsigned long sched_getparam_oracle_anomalies;
	unsigned long sched_rr_get_interval_oracle_anomalies;
	unsigned long get_robust_list_oracle_anomalies;
	unsigned long getrlimit_oracle_anomalies;
	unsigned long sysinfo_oracle_anomalies;
	unsigned long times_oracle_anomalies;
	unsigned long clock_getres_oracle_anomalies;
	unsigned long capget_oracle_anomalies;
	/* Sampled cap-drop invariant fired from periodic_work(): bumped when
	 * a probe that should EPERM under a cap-dropped child instead
	 * succeeds, returns an unexpected errno, or capget(self) reads back
	 * non-empty masks.  See child-capdrop-oracle.c. */
	unsigned long capdrop_oracle_anomalies;
	unsigned long newlstat_oracle_anomalies;
	unsigned long newstat_oracle_anomalies;
	unsigned long newfstat_oracle_anomalies;
	unsigned long newfstatat_oracle_anomalies;
	unsigned long statx_oracle_anomalies;
	unsigned long fstatfs_oracle_anomalies;
	unsigned long fstatfs64_oracle_anomalies;
	unsigned long statfs_oracle_anomalies;
	unsigned long statfs64_oracle_anomalies;
	unsigned long uname_oracle_anomalies;
	unsigned long lsm_list_modules_oracle_anomalies;
	unsigned long listmount_oracle_anomalies;
	unsigned long statmount_oracle_anomalies;
	unsigned long getsockname_oracle_anomalies;
	unsigned long getpeername_oracle_anomalies;
	unsigned long file_getattr_oracle_anomalies;
	unsigned long sched_getattr_oracle_anomalies;
	unsigned long getrusage_oracle_anomalies;
	unsigned long sigpending_oracle_anomalies;
	unsigned long getcpu_oracle_anomalies;
	unsigned long clock_gettime_oracle_anomalies;
	unsigned long get_mempolicy_oracle_anomalies;
	unsigned long lsm_get_self_attr_oracle_anomalies;
	unsigned long prlimit64_oracle_anomalies;
	unsigned long sigaltstack_oracle_anomalies;
	unsigned long olduname_oracle_anomalies;
	unsigned long lookup_dcookie_oracle_anomalies;
	unsigned long getxattr_oracle_anomalies;
	unsigned long lgetxattr_oracle_anomalies;
	unsigned long fgetxattr_oracle_anomalies;
	unsigned long listxattrat_oracle_anomalies;
	unsigned long flistxattr_oracle_anomalies;
	unsigned long listxattr_oracle_anomalies;
	unsigned long llistxattr_oracle_anomalies;
	unsigned long readlink_oracle_anomalies;
	unsigned long readlinkat_oracle_anomalies;
	unsigned long sysfs_oracle_anomalies;
};

#endif /* _TRINITY_STATS_SUBSYS_ORACLE_H */
