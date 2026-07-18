#include <stddef.h>
#include "stats-internal.h"

/*
 * Descriptors for dump_stats_json_oracle().  Every member is named
 * <syscall>_oracle_anomalies in struct oracle_stats but the JSON schema
 * emits it as "<syscall>_anomalies" (the "oracle_" infix is implicit in
 * the enclosing category key), so each row uses STAT_FIELD_JSON_SUB to
 * pin the cross-prefix JSON key.  The JSON walker ignores
 * stat_category.gate_offset (it emits every category unconditionally)
 * and the text dump for oracle stays hand-coded in
 * dump_stats_oracle_anomalies() where each row has its own per-field
 * gate, so fd_oracle_anomalies here is a placeholder gate that matters
 * only if a future change wires stat_category_emit_text() onto this
 * table.
 */
static const struct stat_field oracle_fields[] = {
	STAT_FIELD_JSON_SUB(oracle, fd_oracle_anomalies,                     "fd_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, mmap_oracle_anomalies,                   "mmap_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, cred_oracle_anomalies,                   "cred_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, sched_oracle_anomalies,                  "sched_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, uid_oracle_anomalies,                    "uid_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, gid_oracle_anomalies,                    "gid_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, setgroups_oracle_anomalies,              "setgroups_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getegid_oracle_anomalies,                "getegid_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getuid_oracle_anomalies,                 "getuid_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getgid_oracle_anomalies,                 "getgid_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getppid_oracle_anomalies,                "getppid_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getcwd_oracle_anomalies,                 "getcwd_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getpid_oracle_anomalies,                 "getpid_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getpgid_oracle_anomalies,                "getpgid_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getpgrp_oracle_anomalies,                "getpgrp_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, geteuid_oracle_anomalies,                "geteuid_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getsid_oracle_anomalies,                 "getsid_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, gettid_oracle_anomalies,                 "gettid_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, setsid_oracle_anomalies,                 "setsid_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, setpgid_oracle_anomalies,                "setpgid_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, sched_getscheduler_oracle_anomalies,     "sched_getscheduler_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getgroups_oracle_anomalies,              "getgroups_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getresuid_oracle_anomalies,              "getresuid_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getresgid_oracle_anomalies,              "getresgid_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, umask_oracle_anomalies,                  "umask_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, sched_get_priority_max_oracle_anomalies, "sched_get_priority_max_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, sched_get_priority_min_oracle_anomalies, "sched_get_priority_min_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, sched_yield_oracle_anomalies,            "sched_yield_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getpagesize_oracle_anomalies,            "getpagesize_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, time_oracle_anomalies,                   "time_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, gettimeofday_oracle_anomalies,           "gettimeofday_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, newuname_oracle_anomalies,               "newuname_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, rt_sigpending_oracle_anomalies,          "rt_sigpending_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, sched_getaffinity_oracle_anomalies,      "sched_getaffinity_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, rt_sigprocmask_oracle_anomalies,         "rt_sigprocmask_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, sched_getparam_oracle_anomalies,         "sched_getparam_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, sched_rr_get_interval_oracle_anomalies,  "sched_rr_get_interval_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, get_robust_list_oracle_anomalies,        "get_robust_list_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getrlimit_oracle_anomalies,              "getrlimit_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, sysinfo_oracle_anomalies,                "sysinfo_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, times_oracle_anomalies,                  "times_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, clock_getres_oracle_anomalies,           "clock_getres_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, capget_oracle_anomalies,                 "capget_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, capdrop_oracle_anomalies,                "capdrop_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, newlstat_oracle_anomalies,               "newlstat_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, newstat_oracle_anomalies,                "newstat_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, newfstat_oracle_anomalies,               "newfstat_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, newfstatat_oracle_anomalies,             "newfstatat_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, statx_oracle_anomalies,                  "statx_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, fstatfs_oracle_anomalies,                "fstatfs_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, fstatfs64_oracle_anomalies,              "fstatfs64_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, statfs_oracle_anomalies,                 "statfs_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, statfs64_oracle_anomalies,               "statfs64_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, uname_oracle_anomalies,                  "uname_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, lsm_list_modules_oracle_anomalies,       "lsm_list_modules_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, listmount_oracle_anomalies,              "listmount_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, statmount_oracle_anomalies,              "statmount_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getsockname_oracle_anomalies,            "getsockname_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getpeername_oracle_anomalies,            "getpeername_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, file_getattr_oracle_anomalies,           "file_getattr_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, sched_getattr_oracle_anomalies,          "sched_getattr_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getrusage_oracle_anomalies,              "getrusage_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, sigpending_oracle_anomalies,             "sigpending_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getcpu_oracle_anomalies,                 "getcpu_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, clock_gettime_oracle_anomalies,          "clock_gettime_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, get_mempolicy_oracle_anomalies,          "get_mempolicy_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, lsm_get_self_attr_oracle_anomalies,      "lsm_get_self_attr_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, prlimit64_oracle_anomalies,              "prlimit64_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, sigaltstack_oracle_anomalies,            "sigaltstack_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, olduname_oracle_anomalies,               "olduname_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, lookup_dcookie_oracle_anomalies,         "lookup_dcookie_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, getxattr_oracle_anomalies,               "getxattr_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, lgetxattr_oracle_anomalies,              "lgetxattr_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, fgetxattr_oracle_anomalies,              "fgetxattr_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, listxattrat_oracle_anomalies,            "listxattrat_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, flistxattr_oracle_anomalies,             "flistxattr_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, listxattr_oracle_anomalies,              "listxattr_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, llistxattr_oracle_anomalies,             "llistxattr_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, readlink_oracle_anomalies,               "readlink_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, readlinkat_oracle_anomalies,             "readlinkat_anomalies"),
	STAT_FIELD_JSON_SUB(oracle, sysfs_oracle_anomalies,                  "sysfs_anomalies"),
};

const struct stat_category oracle_category =
	STAT_CATEGORY("oracle",
	              oracle.fd_oracle_anomalies,
	              oracle_fields);
