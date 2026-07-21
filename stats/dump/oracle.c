#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "arch.h"
#include "arg-len-semantics.h"
#include "breadcrumb_ring.h"
#include "child-api.h"
#include "cmp_hints.h"
#include "cred_throttle.h"
#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "reach-band.h"
#include "sequence.h"
#include "shadow_promote.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "strategy.h"		/* frontier_spare_lane_decide, enum frontier_spare_reason */
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "utils-proc.h"
#include "version.h"

/*
 * Per-row descriptor for the oracle anomalies text dump.  One entry per
 * counter; the emitter loop below skips zero-valued rows so quiet runs
 * stay terse, matching the per-field gating the hand-coded chain used.
 *
 * Most rows live under the "oracle" category and follow the
 * <syscall>_oracle_anomalies -> "<syscall>_anomalies" naming pair, but
 * the table keeps each row's category and metric explicit so the two
 * outliers in the set -- post_handler_untouched_out_buf (no
 * _oracle_anomalies suffix on the counter) and statmount_setup_fail
 * (emitted under the "syscall" category, not "oracle") -- sit in line
 * with their siblings instead of needing separate code paths.
 */
struct oracle_anomaly_row {
	const char *category;
	const char *metric;
	size_t      offset;
};

#define ORACLE_ANOMALY_ROW(category_, field_, metric_) \
	{ (category_), (metric_), offsetof(struct stats_s, field_) }

static const struct oracle_anomaly_row oracle_anomaly_rows[] = {
	ORACLE_ANOMALY_ROW("oracle",  oracle.fd_oracle_anomalies,                     "fd_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.mmap_oracle_anomalies,                   "mmap_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.cred_oracle_anomalies,                   "cred_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.sched_oracle_anomalies,                  "sched_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.uid_oracle_anomalies,                    "uid_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.gid_oracle_anomalies,                    "gid_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.setgroups_oracle_anomalies,              "setgroups_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getegid_oracle_anomalies,                "getegid_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getuid_oracle_anomalies,                 "getuid_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getgid_oracle_anomalies,                 "getgid_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getppid_oracle_anomalies,                "getppid_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getcwd_oracle_anomalies,                 "getcwd_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getpid_oracle_anomalies,                 "getpid_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getpgid_oracle_anomalies,                "getpgid_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getpgrp_oracle_anomalies,                "getpgrp_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.geteuid_oracle_anomalies,                "geteuid_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getsid_oracle_anomalies,                 "getsid_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.gettid_oracle_anomalies,                 "gettid_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.setsid_oracle_anomalies,                 "setsid_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.setpgid_oracle_anomalies,                "setpgid_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.sched_getscheduler_oracle_anomalies,     "sched_getscheduler_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getgroups_oracle_anomalies,              "getgroups_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getresuid_oracle_anomalies,              "getresuid_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getresgid_oracle_anomalies,              "getresgid_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.umask_oracle_anomalies,                  "umask_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.sched_get_priority_max_oracle_anomalies, "sched_get_priority_max_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.sched_get_priority_min_oracle_anomalies, "sched_get_priority_min_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.sched_yield_oracle_anomalies,            "sched_yield_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getpagesize_oracle_anomalies,            "getpagesize_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.time_oracle_anomalies,                   "time_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.gettimeofday_oracle_anomalies,           "gettimeofday_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.newuname_oracle_anomalies,               "newuname_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.rt_sigpending_oracle_anomalies,          "rt_sigpending_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.rt_sigprocmask_oracle_anomalies,         "rt_sigprocmask_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.sched_getparam_oracle_anomalies,         "sched_getparam_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.sched_rr_get_interval_oracle_anomalies,  "sched_rr_get_interval_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.get_robust_list_oracle_anomalies,        "get_robust_list_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getrlimit_oracle_anomalies,              "getrlimit_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.sysinfo_oracle_anomalies,                "sysinfo_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.times_oracle_anomalies,                  "times_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.clock_getres_oracle_anomalies,           "clock_getres_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.capget_oracle_anomalies,                 "capget_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.capdrop_oracle_anomalies,                "capdrop_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.newlstat_oracle_anomalies,               "newlstat_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.newstat_oracle_anomalies,                "newstat_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.newfstat_oracle_anomalies,               "newfstat_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  post_handler_untouched_out_buf,                 "untouched_out_buf"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.newfstatat_oracle_anomalies,             "newfstatat_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.statx_oracle_anomalies,                  "statx_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.fstatfs_oracle_anomalies,                "fstatfs_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.fstatfs64_oracle_anomalies,              "fstatfs64_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.statfs_oracle_anomalies,                 "statfs_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.statfs64_oracle_anomalies,               "statfs64_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.uname_oracle_anomalies,                  "uname_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.lsm_list_modules_oracle_anomalies,       "lsm_list_modules_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.listmount_oracle_anomalies,              "listmount_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.statmount_oracle_anomalies,              "statmount_anomalies"),
	ORACLE_ANOMALY_ROW("syscall", diag.statmount_setup_fail,                           "statmount_setup_fail"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getsockname_oracle_anomalies,            "getsockname_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getpeername_oracle_anomalies,            "getpeername_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.file_getattr_oracle_anomalies,           "file_getattr_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.sched_getattr_oracle_anomalies,          "sched_getattr_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getrusage_oracle_anomalies,              "getrusage_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.sigpending_oracle_anomalies,             "sigpending_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getcpu_oracle_anomalies,                 "getcpu_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.clock_gettime_oracle_anomalies,          "clock_gettime_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.get_mempolicy_oracle_anomalies,          "get_mempolicy_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.lsm_get_self_attr_oracle_anomalies,      "lsm_get_self_attr_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.prlimit64_oracle_anomalies,              "prlimit64_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.sigaltstack_oracle_anomalies,            "sigaltstack_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.olduname_oracle_anomalies,               "olduname_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.lookup_dcookie_oracle_anomalies,         "lookup_dcookie_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.getxattr_oracle_anomalies,               "getxattr_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.lgetxattr_oracle_anomalies,              "lgetxattr_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.fgetxattr_oracle_anomalies,              "fgetxattr_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.listxattrat_oracle_anomalies,            "listxattrat_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.flistxattr_oracle_anomalies,             "flistxattr_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.listxattr_oracle_anomalies,              "listxattr_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.llistxattr_oracle_anomalies,             "llistxattr_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.readlink_oracle_anomalies,               "readlink_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.readlinkat_oracle_anomalies,             "readlinkat_anomalies"),
	ORACLE_ANOMALY_ROW("oracle",  oracle.sysfs_oracle_anomalies,                  "sysfs_anomalies"),
};

#undef ORACLE_ANOMALY_ROW

void dump_stats_oracle_anomalies(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(oracle_anomaly_rows); i++) {
		const struct oracle_anomaly_row *r = &oracle_anomaly_rows[i];
		unsigned long v = *(const unsigned long *)
			((const char *)&shm->stats + r->offset);

		if (v)
			stat_row(r->category, r->metric, v);
	}
}
