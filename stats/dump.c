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
#include "child.h"
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
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "version.h"

/*
 * Pure-render stats dump emitters carved out of stats.c.
 *
 * Behaviour-neutral by construction: the original function bodies are
 * moved verbatim.  Shared file-scope helpers and the stat_category
 * tables they read stay defined in stats.c; their `static` qualifier
 * was dropped at the carve point and prototypes/externs are exposed
 * via stats-internal.h.
 *
 * Excluded from the carve are dump emitters with non-trivial state
 * transitions (notably kcov_cmp_stats_periodic_dump, which gates on
 * elapsed time and maintains a prev-window snapshot) -- those stay in
 * stats.c until they get their own dedicated audit.
 */

void dump_stats_oracle_anomalies(void)
{
	if (shm->stats.fd_oracle_anomalies)
		stat_row("oracle", "fd_anomalies",   shm->stats.fd_oracle_anomalies);
	if (shm->stats.mmap_oracle_anomalies)
		stat_row("oracle", "mmap_anomalies", shm->stats.mmap_oracle_anomalies);
	if (shm->stats.cred_oracle_anomalies)
		stat_row("oracle", "cred_anomalies", shm->stats.cred_oracle_anomalies);
	if (shm->stats.sched_oracle_anomalies)
		stat_row("oracle", "sched_anomalies", shm->stats.sched_oracle_anomalies);
	if (shm->stats.uid_oracle_anomalies)
		stat_row("oracle", "uid_anomalies",   shm->stats.uid_oracle_anomalies);
	if (shm->stats.gid_oracle_anomalies)
		stat_row("oracle", "gid_anomalies",   shm->stats.gid_oracle_anomalies);
	if (shm->stats.setgroups_oracle_anomalies)
		stat_row("oracle", "setgroups_anomalies", shm->stats.setgroups_oracle_anomalies);
	if (shm->stats.getegid_oracle_anomalies)
		stat_row("oracle", "getegid_anomalies", shm->stats.getegid_oracle_anomalies);
	if (shm->stats.getuid_oracle_anomalies)
		stat_row("oracle", "getuid_anomalies", shm->stats.getuid_oracle_anomalies);
	if (shm->stats.getgid_oracle_anomalies)
		stat_row("oracle", "getgid_anomalies", shm->stats.getgid_oracle_anomalies);
	if (shm->stats.getppid_oracle_anomalies)
		stat_row("oracle", "getppid_anomalies", shm->stats.getppid_oracle_anomalies);
	if (shm->stats.getcwd_oracle_anomalies)
		stat_row("oracle", "getcwd_anomalies", shm->stats.getcwd_oracle_anomalies);
	if (shm->stats.getpid_oracle_anomalies)
		stat_row("oracle", "getpid_anomalies", shm->stats.getpid_oracle_anomalies);
	if (shm->stats.getpgid_oracle_anomalies)
		stat_row("oracle", "getpgid_anomalies", shm->stats.getpgid_oracle_anomalies);
	if (shm->stats.getpgrp_oracle_anomalies)
		stat_row("oracle", "getpgrp_anomalies", shm->stats.getpgrp_oracle_anomalies);
	if (shm->stats.geteuid_oracle_anomalies)
		stat_row("oracle", "geteuid_anomalies", shm->stats.geteuid_oracle_anomalies);
	if (shm->stats.getsid_oracle_anomalies)
		stat_row("oracle", "getsid_anomalies", shm->stats.getsid_oracle_anomalies);
	if (shm->stats.gettid_oracle_anomalies)
		stat_row("oracle", "gettid_anomalies", shm->stats.gettid_oracle_anomalies);
	if (shm->stats.setsid_oracle_anomalies)
		stat_row("oracle", "setsid_anomalies", shm->stats.setsid_oracle_anomalies);
	if (shm->stats.setpgid_oracle_anomalies)
		stat_row("oracle", "setpgid_anomalies", shm->stats.setpgid_oracle_anomalies);
	if (shm->stats.sched_getscheduler_oracle_anomalies)
		stat_row("oracle", "sched_getscheduler_anomalies",
			 shm->stats.sched_getscheduler_oracle_anomalies);
	if (shm->stats.getgroups_oracle_anomalies)
		stat_row("oracle", "getgroups_anomalies", shm->stats.getgroups_oracle_anomalies);
	if (shm->stats.getresuid_oracle_anomalies)
		stat_row("oracle", "getresuid_anomalies", shm->stats.getresuid_oracle_anomalies);
	if (shm->stats.getresgid_oracle_anomalies)
		stat_row("oracle", "getresgid_anomalies", shm->stats.getresgid_oracle_anomalies);
	if (shm->stats.umask_oracle_anomalies)
		stat_row("oracle", "umask_anomalies", shm->stats.umask_oracle_anomalies);
	if (shm->stats.sched_get_priority_max_oracle_anomalies)
		stat_row("oracle", "sched_get_priority_max_anomalies",
			 shm->stats.sched_get_priority_max_oracle_anomalies);
	if (shm->stats.sched_get_priority_min_oracle_anomalies)
		stat_row("oracle", "sched_get_priority_min_anomalies",
			 shm->stats.sched_get_priority_min_oracle_anomalies);
	if (shm->stats.sched_yield_oracle_anomalies)
		stat_row("oracle", "sched_yield_anomalies",
			 shm->stats.sched_yield_oracle_anomalies);
	if (shm->stats.getpagesize_oracle_anomalies)
		stat_row("oracle", "getpagesize_anomalies",
			 shm->stats.getpagesize_oracle_anomalies);
	if (shm->stats.time_oracle_anomalies)
		stat_row("oracle", "time_anomalies",
			 shm->stats.time_oracle_anomalies);
	if (shm->stats.gettimeofday_oracle_anomalies)
		stat_row("oracle", "gettimeofday_anomalies",
			 shm->stats.gettimeofday_oracle_anomalies);
	if (shm->stats.newuname_oracle_anomalies)
		stat_row("oracle", "newuname_anomalies",
			 shm->stats.newuname_oracle_anomalies);
	if (shm->stats.rt_sigpending_oracle_anomalies)
		stat_row("oracle", "rt_sigpending_anomalies",
			 shm->stats.rt_sigpending_oracle_anomalies);
	if (shm->stats.rt_sigprocmask_oracle_anomalies)
		stat_row("oracle", "rt_sigprocmask_anomalies",
			 shm->stats.rt_sigprocmask_oracle_anomalies);
	if (shm->stats.sched_getparam_oracle_anomalies)
		stat_row("oracle", "sched_getparam_anomalies",
			 shm->stats.sched_getparam_oracle_anomalies);
	if (shm->stats.sched_rr_get_interval_oracle_anomalies)
		stat_row("oracle", "sched_rr_get_interval_anomalies",
			 shm->stats.sched_rr_get_interval_oracle_anomalies);
	if (shm->stats.get_robust_list_oracle_anomalies)
		stat_row("oracle", "get_robust_list_anomalies",
			 shm->stats.get_robust_list_oracle_anomalies);
	if (shm->stats.getrlimit_oracle_anomalies)
		stat_row("oracle", "getrlimit_anomalies",
			 shm->stats.getrlimit_oracle_anomalies);
	if (shm->stats.sysinfo_oracle_anomalies)
		stat_row("oracle", "sysinfo_anomalies",
			 shm->stats.sysinfo_oracle_anomalies);
	if (shm->stats.times_oracle_anomalies)
		stat_row("oracle", "times_anomalies",
			 shm->stats.times_oracle_anomalies);
	if (shm->stats.clock_getres_oracle_anomalies)
		stat_row("oracle", "clock_getres_anomalies",
			 shm->stats.clock_getres_oracle_anomalies);
	if (shm->stats.capget_oracle_anomalies)
		stat_row("oracle", "capget_anomalies",
			 shm->stats.capget_oracle_anomalies);
	if (shm->stats.capdrop_oracle_anomalies)
		stat_row("oracle", "capdrop_anomalies",
			 shm->stats.capdrop_oracle_anomalies);
	if (shm->stats.newlstat_oracle_anomalies)
		stat_row("oracle", "newlstat_anomalies",
			 shm->stats.newlstat_oracle_anomalies);
	if (shm->stats.newstat_oracle_anomalies)
		stat_row("oracle", "newstat_anomalies",
			 shm->stats.newstat_oracle_anomalies);
	if (shm->stats.newfstat_oracle_anomalies)
		stat_row("oracle", "newfstat_anomalies",
			 shm->stats.newfstat_oracle_anomalies);
	if (shm->stats.post_handler_untouched_out_buf)
		stat_row("oracle", "untouched_out_buf",
			 shm->stats.post_handler_untouched_out_buf);
	if (shm->stats.newfstatat_oracle_anomalies)
		stat_row("oracle", "newfstatat_anomalies",
			 shm->stats.newfstatat_oracle_anomalies);
	if (shm->stats.statx_oracle_anomalies)
		stat_row("oracle", "statx_anomalies",
			 shm->stats.statx_oracle_anomalies);
	if (shm->stats.fstatfs_oracle_anomalies)
		stat_row("oracle", "fstatfs_anomalies",
			 shm->stats.fstatfs_oracle_anomalies);
	if (shm->stats.fstatfs64_oracle_anomalies)
		stat_row("oracle", "fstatfs64_anomalies",
			 shm->stats.fstatfs64_oracle_anomalies);
	if (shm->stats.statfs_oracle_anomalies)
		stat_row("oracle", "statfs_anomalies",
			 shm->stats.statfs_oracle_anomalies);
	if (shm->stats.statfs64_oracle_anomalies)
		stat_row("oracle", "statfs64_anomalies",
			 shm->stats.statfs64_oracle_anomalies);
	if (shm->stats.uname_oracle_anomalies)
		stat_row("oracle", "uname_anomalies",
			 shm->stats.uname_oracle_anomalies);
	if (shm->stats.lsm_list_modules_oracle_anomalies)
		stat_row("oracle", "lsm_list_modules_anomalies",
			 shm->stats.lsm_list_modules_oracle_anomalies);
	if (shm->stats.listmount_oracle_anomalies)
		stat_row("oracle", "listmount_anomalies",
			 shm->stats.listmount_oracle_anomalies);
	if (shm->stats.statmount_oracle_anomalies)
		stat_row("oracle", "statmount_anomalies",
			 shm->stats.statmount_oracle_anomalies);
	if (shm->stats.statmount_setup_fail)
		stat_row("syscall", "statmount_setup_fail",
			 shm->stats.statmount_setup_fail);
	if (shm->stats.getsockname_oracle_anomalies)
		stat_row("oracle", "getsockname_anomalies",
			 shm->stats.getsockname_oracle_anomalies);
	if (shm->stats.getpeername_oracle_anomalies)
		stat_row("oracle", "getpeername_anomalies",
			 shm->stats.getpeername_oracle_anomalies);
	if (shm->stats.file_getattr_oracle_anomalies)
		stat_row("oracle", "file_getattr_anomalies",
			 shm->stats.file_getattr_oracle_anomalies);
	if (shm->stats.sched_getattr_oracle_anomalies)
		stat_row("oracle", "sched_getattr_anomalies",
			 shm->stats.sched_getattr_oracle_anomalies);
	if (shm->stats.getrusage_oracle_anomalies)
		stat_row("oracle", "getrusage_anomalies",
			 shm->stats.getrusage_oracle_anomalies);
	if (shm->stats.sigpending_oracle_anomalies)
		stat_row("oracle", "sigpending_anomalies",
			 shm->stats.sigpending_oracle_anomalies);
	if (shm->stats.getcpu_oracle_anomalies)
		stat_row("oracle", "getcpu_anomalies",
			 shm->stats.getcpu_oracle_anomalies);
	if (shm->stats.clock_gettime_oracle_anomalies)
		stat_row("oracle", "clock_gettime_anomalies",
			 shm->stats.clock_gettime_oracle_anomalies);
	if (shm->stats.get_mempolicy_oracle_anomalies)
		stat_row("oracle", "get_mempolicy_anomalies",
			 shm->stats.get_mempolicy_oracle_anomalies);
	if (shm->stats.lsm_get_self_attr_oracle_anomalies)
		stat_row("oracle", "lsm_get_self_attr_anomalies",
			 shm->stats.lsm_get_self_attr_oracle_anomalies);
	if (shm->stats.prlimit64_oracle_anomalies)
		stat_row("oracle", "prlimit64_anomalies",
			 shm->stats.prlimit64_oracle_anomalies);
	if (shm->stats.sigaltstack_oracle_anomalies)
		stat_row("oracle", "sigaltstack_anomalies",
			 shm->stats.sigaltstack_oracle_anomalies);
	if (shm->stats.olduname_oracle_anomalies)
		stat_row("oracle", "olduname_anomalies",
			 shm->stats.olduname_oracle_anomalies);
	if (shm->stats.lookup_dcookie_oracle_anomalies)
		stat_row("oracle", "lookup_dcookie_anomalies",
			 shm->stats.lookup_dcookie_oracle_anomalies);
	if (shm->stats.getxattr_oracle_anomalies)
		stat_row("oracle", "getxattr_anomalies",
			 shm->stats.getxattr_oracle_anomalies);
	if (shm->stats.lgetxattr_oracle_anomalies)
		stat_row("oracle", "lgetxattr_anomalies",
			 shm->stats.lgetxattr_oracle_anomalies);
	if (shm->stats.fgetxattr_oracle_anomalies)
		stat_row("oracle", "fgetxattr_anomalies",
			 shm->stats.fgetxattr_oracle_anomalies);
	if (shm->stats.listxattrat_oracle_anomalies)
		stat_row("oracle", "listxattrat_anomalies",
			 shm->stats.listxattrat_oracle_anomalies);
	if (shm->stats.flistxattr_oracle_anomalies)
		stat_row("oracle", "flistxattr_anomalies",
			 shm->stats.flistxattr_oracle_anomalies);
	if (shm->stats.listxattr_oracle_anomalies)
		stat_row("oracle", "listxattr_anomalies",
			 shm->stats.listxattr_oracle_anomalies);
	if (shm->stats.llistxattr_oracle_anomalies)
		stat_row("oracle", "llistxattr_anomalies",
			 shm->stats.llistxattr_oracle_anomalies);
	if (shm->stats.readlink_oracle_anomalies)
		stat_row("oracle", "readlink_anomalies",
			 shm->stats.readlink_oracle_anomalies);
	if (shm->stats.readlinkat_oracle_anomalies)
		stat_row("oracle", "readlinkat_anomalies",
			 shm->stats.readlinkat_oracle_anomalies);
	if (shm->stats.sysfs_oracle_anomalies)
		stat_row("oracle", "sysfs_anomalies",
			 shm->stats.sysfs_oracle_anomalies);
}

void dump_stats_fuzzer_subsystems(void)
{
	if (shm->stats.procfs_writes_open_fail || shm->stats.procfs_writes_write_fail ||
	    shm->stats.procfs_writes_write_ok ||
	    shm->stats.sysfs_writes_open_fail || shm->stats.sysfs_writes_write_fail ||
	    shm->stats.sysfs_writes_write_ok ||
	    shm->stats.debugfs_writes_open_fail || shm->stats.debugfs_writes_write_fail ||
	    shm->stats.debugfs_writes_write_ok) {
		stat_row("vfs_writes", "procfs_open_fail",   shm->stats.procfs_writes_open_fail);
		stat_row("vfs_writes", "procfs_write_fail",  shm->stats.procfs_writes_write_fail);
		stat_row("vfs_writes", "procfs_write_ok",    shm->stats.procfs_writes_write_ok);
		stat_row("vfs_writes", "sysfs_open_fail",    shm->stats.sysfs_writes_open_fail);
		stat_row("vfs_writes", "sysfs_write_fail",   shm->stats.sysfs_writes_write_fail);
		stat_row("vfs_writes", "sysfs_write_ok",     shm->stats.sysfs_writes_write_ok);
		stat_row("vfs_writes", "debugfs_open_fail",  shm->stats.debugfs_writes_open_fail);
		stat_row("vfs_writes", "debugfs_write_fail", shm->stats.debugfs_writes_write_fail);
		stat_row("vfs_writes", "debugfs_write_ok",   shm->stats.debugfs_writes_write_ok);
	}

	if (shm->stats.memory_pressure_runs)
		stat_row("memory_pressure", "runs_madv_pageout", shm->stats.memory_pressure_runs);

	stat_category_emit_text(&sched_cycler_category);

	stat_category_emit_text(&userns_fuzzer_category);

	stat_category_emit_text(&userns_bootstrap_category);

	stat_category_emit_text(&barrier_racer_category);

	if (shm->stats.genetlink_families_discovered ||
	    shm->stats.genetlink_msgs_sent              ||
	    shm->stats.genetlink_missing_producer       ||
	    shm->stats.genetlink_discovery_io_err       ||
	    shm->stats.genetlink_discovery_nlerr) {
		stat_row("genetlink_fuzzer", "families_discovered", shm->stats.genetlink_families_discovered);
		stat_row("genetlink_fuzzer", "msgs_sent",           shm->stats.genetlink_msgs_sent);
		stat_row("genetlink_fuzzer", "eperm",               shm->stats.genetlink_eperm);
		stat_row("genetlink_fuzzer", "stale_seq_drops",     shm->stats.genetlink_stale_seq_drops);
		stat_row("genetlink_fuzzer", "missing_producer",    shm->stats.genetlink_missing_producer);
		stat_row("genetlink_fuzzer", "discovery_io_err",    shm->stats.genetlink_discovery_io_err);
		stat_row("genetlink_fuzzer", "discovery_nlerr",     shm->stats.genetlink_discovery_nlerr);
	}

	if (shm->stats.genl_family_calls_devlink   ||
	    shm->stats.genl_family_calls_nl80211   ||
	    shm->stats.genl_family_calls_taskstats ||
	    shm->stats.genl_family_calls_ethtool   ||
	    shm->stats.genl_family_calls_mptcp_pm  ||
	    shm->stats.genl_family_calls_tipc      ||
	    shm->stats.genl_family_calls_wireguard ||
	    shm->stats.genl_family_calls_netlabel  ||
	    shm->stats.genl_family_calls_team      ||
	    shm->stats.genl_family_calls_hsr       ||
	    shm->stats.genl_family_calls_fou       ||
	    shm->stats.genl_family_calls_psample   ||
	    shm->stats.genl_family_calls_nfsd      ||
	    shm->stats.genl_family_calls_ila       ||
	    shm->stats.genl_family_calls_ioam6     ||
	    shm->stats.genl_family_calls_seg6      ||
	    shm->stats.genl_family_calls_thermal   ||
	    shm->stats.genl_family_calls_ipvs) {
		stat_row("genl_family_calls", "devlink",   shm->stats.genl_family_calls_devlink);
		stat_row("genl_family_calls", "nl80211",   shm->stats.genl_family_calls_nl80211);
		stat_row("genl_family_calls", "taskstats", shm->stats.genl_family_calls_taskstats);
		stat_row("genl_family_calls", "ethtool",   shm->stats.genl_family_calls_ethtool);
		stat_row("genl_family_calls", "mptcp_pm",  shm->stats.genl_family_calls_mptcp_pm);
		stat_row("genl_family_calls", "tipc",      shm->stats.genl_family_calls_tipc);
		stat_row("genl_family_calls", "wireguard", shm->stats.genl_family_calls_wireguard);
		stat_row("genl_family_calls", "netlabel",  shm->stats.genl_family_calls_netlabel);
		stat_row("genl_family_calls", "team",      shm->stats.genl_family_calls_team);
		stat_row("genl_family_calls", "hsr",       shm->stats.genl_family_calls_hsr);
		stat_row("genl_family_calls", "fou",       shm->stats.genl_family_calls_fou);
		stat_row("genl_family_calls", "psample",   shm->stats.genl_family_calls_psample);
		stat_row("genl_family_calls", "nfsd",      shm->stats.genl_family_calls_nfsd);
		stat_row("genl_family_calls", "ila",       shm->stats.genl_family_calls_ila);
		stat_row("genl_family_calls", "ioam6",     shm->stats.genl_family_calls_ioam6);
		stat_row("genl_family_calls", "seg6",      shm->stats.genl_family_calls_seg6);
		stat_row("genl_family_calls", "thermal",   shm->stats.genl_family_calls_thermal);
		stat_row("genl_family_calls", "ipvs",      shm->stats.genl_family_calls_ipvs);
	}

	if (shm->stats.nfnl_subsys_calls_ctnetlink     ||
	    shm->stats.nfnl_subsys_calls_ctnetlink_exp ||
	    shm->stats.nfnl_subsys_calls_nftables      ||
	    shm->stats.nfnl_subsys_calls_ipset) {
		stat_row("nfnl_subsys_calls", "ctnetlink",     shm->stats.nfnl_subsys_calls_ctnetlink);
		stat_row("nfnl_subsys_calls", "ctnetlink_exp", shm->stats.nfnl_subsys_calls_ctnetlink_exp);
		stat_row("nfnl_subsys_calls", "nftables",      shm->stats.nfnl_subsys_calls_nftables);
		stat_row("nfnl_subsys_calls", "ipset",         shm->stats.nfnl_subsys_calls_ipset);
	}

	if (shm->stats.netlink_nested_attrs_emitted)
		stat_row("netlink_generator", "nested_attrs_emitted", shm->stats.netlink_nested_attrs_emitted);

	if (shm->stats.kvm_vcpu_ioctls_dispatched)
		stat_row("kvm", "vcpu_ioctls_dispatched", shm->stats.kvm_vcpu_ioctls_dispatched);

	if (shm->stats.kvm_vm_ioctls_dispatched)
		stat_row("kvm", "vm_ioctls_dispatched", shm->stats.kvm_vm_ioctls_dispatched);

	stat_category_emit_text(&perf_event_chains_category);

	if (shm->stats.tracefs_kprobe_writes_open_fail || shm->stats.tracefs_kprobe_writes_write_fail ||
	    shm->stats.tracefs_kprobe_writes_write_ok ||
	    shm->stats.tracefs_uprobe_writes_open_fail || shm->stats.tracefs_uprobe_writes_write_fail ||
	    shm->stats.tracefs_uprobe_writes_write_ok ||
	    shm->stats.tracefs_filter_writes_open_fail || shm->stats.tracefs_filter_writes_write_fail ||
	    shm->stats.tracefs_filter_writes_write_ok ||
	    shm->stats.tracefs_event_enable_writes_open_fail || shm->stats.tracefs_event_enable_writes_write_fail ||
	    shm->stats.tracefs_event_enable_writes_write_ok ||
	    shm->stats.tracefs_misc_writes_open_fail || shm->stats.tracefs_misc_writes_write_fail ||
	    shm->stats.tracefs_misc_writes_write_ok) {
		stat_row("tracefs_fuzzer", "kprobe_open_fail",         shm->stats.tracefs_kprobe_writes_open_fail);
		stat_row("tracefs_fuzzer", "kprobe_write_fail",        shm->stats.tracefs_kprobe_writes_write_fail);
		stat_row("tracefs_fuzzer", "kprobe_write_ok",          shm->stats.tracefs_kprobe_writes_write_ok);
		stat_row("tracefs_fuzzer", "uprobe_open_fail",         shm->stats.tracefs_uprobe_writes_open_fail);
		stat_row("tracefs_fuzzer", "uprobe_write_fail",        shm->stats.tracefs_uprobe_writes_write_fail);
		stat_row("tracefs_fuzzer", "uprobe_write_ok",          shm->stats.tracefs_uprobe_writes_write_ok);
		stat_row("tracefs_fuzzer", "filter_open_fail",         shm->stats.tracefs_filter_writes_open_fail);
		stat_row("tracefs_fuzzer", "filter_write_fail",        shm->stats.tracefs_filter_writes_write_fail);
		stat_row("tracefs_fuzzer", "filter_write_ok",          shm->stats.tracefs_filter_writes_write_ok);
		stat_row("tracefs_fuzzer", "event_enable_open_fail",   shm->stats.tracefs_event_enable_writes_open_fail);
		stat_row("tracefs_fuzzer", "event_enable_write_fail",  shm->stats.tracefs_event_enable_writes_write_fail);
		stat_row("tracefs_fuzzer", "event_enable_write_ok",    shm->stats.tracefs_event_enable_writes_write_ok);
		stat_row("tracefs_fuzzer", "misc_open_fail",           shm->stats.tracefs_misc_writes_open_fail);
		stat_row("tracefs_fuzzer", "misc_write_fail",          shm->stats.tracefs_misc_writes_write_fail);
		stat_row("tracefs_fuzzer", "misc_write_ok",            shm->stats.tracefs_misc_writes_write_ok);
	}

	stat_category_emit_text(&bpf_lifecycle_category);

	if (shm->stats.bpf_maps_provided || shm->stats.bpf_progs_provided) {
		stat_row("bpf_fd_provider", "maps_provided",  shm->stats.bpf_maps_provided);
		stat_row("bpf_fd_provider", "progs_provided", shm->stats.bpf_progs_provided);
	}

	if (shm->stats.ebpf_gen_map_fd_substituted) {
		stat_row("ebpf_gen", "map_fd_substituted",
			 shm->stats.ebpf_gen_map_fd_substituted);
	}

	if (shm->stats.ebpf_gen_helper_call_emitted) {
		stat_row("ebpf_gen", "helper_call_emitted",
			 shm->stats.ebpf_gen_helper_call_emitted);
	}

	if (shm->stats.ebpf_gen_map_value_deref_emitted) {
		stat_row("ebpf_gen", "map_value_deref_emitted",
			 shm->stats.ebpf_gen_map_value_deref_emitted);
		stat_row("ebpf_gen", "map_value_deref_read",
			 shm->stats.ebpf_gen_map_value_deref_read);
		stat_row("ebpf_gen", "map_value_deref_write",
			 shm->stats.ebpf_gen_map_value_deref_write);
	}

	if (shm->stats.recipe_runs) {
		stat_row("recipe_runner", "runs",        shm->stats.recipe_runs);
		stat_row("recipe_runner", "completed",   shm->stats.recipe_completed);
		stat_row("recipe_runner", "partial",     shm->stats.recipe_partial);
		stat_row("recipe_runner", "unsupported", shm->stats.recipe_unsupported);
		recipe_runner_dump_stats();
	}

	if (shm->stats.iouring_recipes_runs) {
		stat_row("iouring_recipes", "runs",      shm->stats.iouring_recipes_runs);
		stat_row("iouring_recipes", "completed", shm->stats.iouring_recipes_completed);
		stat_row("iouring_recipes", "partial",   shm->stats.iouring_recipes_partial);
		stat_row("iouring_recipes", "enosys",    shm->stats.iouring_recipes_enosys);
		iouring_recipes_dump_stats();
	}

	if (shm->stats.iouring_eventfd_register_ok ||
	    shm->stats.iouring_eventfd_register_fail) {
		stat_row("iouring_eventfd", "register_ok",
			 shm->stats.iouring_eventfd_register_ok);
		stat_row("iouring_eventfd", "register_fail",
			 shm->stats.iouring_eventfd_register_fail);
		stat_row("iouring_eventfd", "recursive_runs",
			 shm->stats.iouring_eventfd_recursive_runs);
		stat_row("iouring_eventfd", "recursive_cqes",
			 shm->stats.iouring_eventfd_recursive_cqes);
	}

	stat_category_emit_text(&aio_category);

	stat_category_emit_text(&errno_gradient_category);

	stat_category_emit_text(&cold_overflow_category);

	stat_category_emit_text(&inplace_crypto_category);

	stat_category_emit_text(&fd_runtime_skipped_category);

	if (shm->stats.zombies_reaped || shm->stats.zombies_timed_out ||
	    shm->stats.zombie_slots_pending) {
		stat_row("zombie_slots", "pending",   shm->stats.zombie_slots_pending);
		stat_row("zombie_slots", "reaped",    shm->stats.zombies_reaped);
		stat_row("zombie_slots", "timed_out", shm->stats.zombies_timed_out);
	}
}

void dump_stats_corruption_and_pool(void)
{
	if (shm->stats.fd_event_ring_corrupted)
		stat_row("corruption", "fd_event_ring_noncanon", shm->stats.fd_event_ring_corrupted);
	if (shm->stats.fd_event_ring_overwritten)
		stat_row("corruption", "fd_event_ring_canary",   shm->stats.fd_event_ring_overwritten);
	if (shm->stats.stats_ring_corrupted)
		stat_row("corruption", "stats_ring_noncanon",    shm->stats.stats_ring_corrupted);
	if (shm->stats.stats_ring_overwritten)
		stat_row("corruption", "stats_ring_canary",      shm->stats.stats_ring_overwritten);
	if (shm->stats.fd_event_payload_corrupt)
		stat_row("corruption", "fd_event_payload",       shm->stats.fd_event_payload_corrupt);
	if (parent_stats.deferred_free_corrupt_ptr)
		stat_row("corruption", "deferred_free_corrupt_ptr", parent_stats.deferred_free_corrupt_ptr);
	if (parent_stats.post_handler_corrupt_ptr)
		stat_row("corruption", "post_handler_corrupt_ptr", parent_stats.post_handler_corrupt_ptr);
	/*
	 * Standalone grep-friendly cumulative line.  The stat_row above
	 * is gated on non-zero and the per-handler attribution block
	 * elsewhere repeats the bare token "post_handler_corrupt_ptr"
	 * as narrative, so `grep -c post_handler_corrupt_ptr out.log`
	 * counts occurrences, not the counter -- a triage trap.  Emit
	 * one line per window with a distinctive _cumulative suffix so
	 * operators can do `grep post_handler_corrupt_ptr_cumulative
	 * out.log | tail -1` for the current total, or grep -c against
	 * the suffix to count windows.
	 */
	output(0, "[main] post_handler_corrupt_ptr_cumulative=%lu\n",
	       parent_stats.post_handler_corrupt_ptr);
	/*
	 * TRINITY_CORRUPT_ATTRIB per-call-site breakdown.  Gated on the
	 * env-var-latched bool so production dumps stay terse; when on,
	 * emits one stat_row per named site plus a computed "post_generic"
	 * row carrying the residual headline - sum(named).  A non-trivial
	 * post_generic value is the lead for the next call-site sweep --
	 * the producer is some legacy post_handler_corrupt_ptr_bump() macro
	 * caller that hasn't been categorised yet.  Reads shm->stats via
	 * RELAXED atomic loads since children are concurrent writers.
	 */
	if (corrupt_ptr_attrib_active()) {
		unsigned long named_sum = 0;
		unsigned long total = parent_stats.post_handler_corrupt_ptr;
		unsigned int i;

		for (i = 0; i < CORRUPT_PTR_SITE__COUNT; i++) {
			unsigned long v;
			char metric[64];

			v = __atomic_load_n(&shm->stats.corrupt_ptr_site_count[i],
					    __ATOMIC_RELAXED);
			named_sum += v;
			snprintf(metric, sizeof(metric),
				 "corrupt_ptr_site:%s",
				 corrupt_ptr_site_names[i]);
			stat_row("corruption", metric, v);
			output(0, "[main] %s_cumulative=%lu\n", metric, v);
		}
		/* Anything in the headline not claimed by a named site:
		 * the legacy post_handler_corrupt_ptr_bump(rec, NULL) callers
		 * in syscalls (the per-handler oracle bumps that weren't
		 * routed through _at()).  Saturate to zero if named_sum
		 * outruns the headline due to non-atomic reads of the two
		 * counters at slightly different moments. */
		stat_row("corruption", "corrupt_ptr_site:post_generic",
			 total > named_sum ? total - named_sum : 0);
		output(0, "[main] corrupt_ptr_site:post_generic_cumulative=%lu (headline=%lu named_sum=%lu)\n",
		       total > named_sum ? total - named_sum : 0,
		       total, named_sum);
	}
	if (parent_stats.arg_shadow_stomp)
		stat_row("corruption", "arg_shadow_stomp", parent_stats.arg_shadow_stomp);
	if (parent_stats.deferred_free_reject)
		stat_row("corruption", "deferred_free_reject",   parent_stats.deferred_free_reject);
	if (parent_stats.deferred_free_reject_pathname)
		stat_row("corruption", "deferred_free_reject_pathname", parent_stats.deferred_free_reject_pathname);
	if (parent_stats.deferred_free_reject_iovec)
		stat_row("corruption", "deferred_free_reject_iovec", parent_stats.deferred_free_reject_iovec);
	if (parent_stats.deferred_free_reject_sockaddr)
		stat_row("corruption", "deferred_free_reject_sockaddr", parent_stats.deferred_free_reject_sockaddr);
	if (parent_stats.deferred_free_reject_other)
		stat_row("corruption", "deferred_free_reject_other", parent_stats.deferred_free_reject_other);
	if (shm->stats.deferred_free_reject_misaligned)
		stat_row("corruption", "deferred_free_reject_misaligned",     shm->stats.deferred_free_reject_misaligned);
	if (shm->stats.deferred_free_reject_corrupt_shape)
		stat_row("corruption", "deferred_free_reject_corrupt_shape",  shm->stats.deferred_free_reject_corrupt_shape);
	if (shm->stats.deferred_free_reject_non_heap)
		stat_row("corruption", "deferred_free_reject_non_heap",       shm->stats.deferred_free_reject_non_heap);
	if (shm->stats.deferred_free_reject_untracked)
		stat_row("corruption", "deferred_free_reject_untracked",      shm->stats.deferred_free_reject_untracked);
	if (shm->stats.nested_scrub_reject_untracked)
		stat_row("corruption", "nested_scrub_reject_untracked",       shm->stats.nested_scrub_reject_untracked);
	if (shm->stats.deferred_free_reject_shared_region)
		stat_row("corruption", "deferred_free_reject_shared_region",  shm->stats.deferred_free_reject_shared_region);
	if (shm->stats.deferred_free_outstanding_vmas)
		stat_row("corruption", "deferred_free_outstanding_vmas",      shm->stats.deferred_free_outstanding_vmas);
	if (shm->stats.deferred_free_vma_fallback_immediate)
		stat_row("corruption", "deferred_free_vma_fallback_immediate", shm->stats.deferred_free_vma_fallback_immediate);
	if (shm->stats.deferred_free_enomem_drain)
		stat_row("corruption", "deferred_free_enomem_drain",          shm->stats.deferred_free_enomem_drain);
	if (shm->stats.deferred_free_rw_restore_enomem)
		stat_row("corruption", "deferred_free_rw_restore_enomem",     shm->stats.deferred_free_rw_restore_enomem);
	if (shm->stats.deferred_free_pre_dispatch_leaked)
		stat_row("corruption", "deferred_free_pre_dispatch_leaked",   shm->stats.deferred_free_pre_dispatch_leaked);
	if (shm->stats.ring_evict_leaked)
		stat_row("corruption", "ring_evict_leaked",                   shm->stats.ring_evict_leaked);
	if (shm->stats.deferred_free_ring_owned_skip)
		stat_row("corruption", "deferred_free_ring_owned_skip",       shm->stats.deferred_free_ring_owned_skip);
	if (shm->stats.deferred_free_double_admit_skip)
		stat_row("corruption", "deferred_free_double_admit_skip",     shm->stats.deferred_free_double_admit_skip);
	if (shm->stats.alloc_track_refresh_ring_owned_skip)
		stat_row("corruption", "alloc_track_refresh_ring_owned_skip", shm->stats.alloc_track_refresh_ring_owned_skip);
	if (shm->stats.alloc_track_refresh_unverified_skip)
		stat_row("corruption", "alloc_track_refresh_unverified_skip", shm->stats.alloc_track_refresh_unverified_skip);
	if (parent_stats.snapshot_non_heap_reject)
		stat_row("corruption", "snapshot_non_heap_reject", parent_stats.snapshot_non_heap_reject);
	if (parent_stats.lock_word_scribbled)
		stat_row("corruption", "lock_word_scribbled",   parent_stats.lock_word_scribbled);
	if (shm->stats.lock_held_scribble)
		stat_row("corruption", "lock_held_scribble",    shm->stats.lock_held_scribble);
	if (shm->stats.rec_canary_stomped)
		stat_row("corruption", "rec_canary_stomped",     shm->stats.rec_canary_stomped);
	if (shm->stats.mut_attrib_inversion_caught)
		stat_row("corruption", "mut_attrib_inversion_caught",
			 shm->stats.mut_attrib_inversion_caught);
	if (shm->stats.rzs_blanket_reject)
		stat_row("corruption", "rzs_blanket_reject",     shm->stats.rzs_blanket_reject);
	if (shm->stats.retfd_blanket_reject)
		stat_row("corruption", "retfd_blanket_reject",   shm->stats.retfd_blanket_reject);
	if (shm->stats.arena_ptr_stale_caught_arg)
		stat_row("corruption", "arena_ptr_stale_caught_arg",
			 shm->stats.arena_ptr_stale_caught_arg);
	if (shm->stats.arena_ptr_stale_caught_post_state)
		stat_row("corruption", "arena_ptr_stale_caught_post_state",
			 shm->stats.arena_ptr_stale_caught_post_state);
	/*
	 * Standalone grep-friendly cumulative lines for the arena_ptr_stale
	 * pair.  The stat_rows above are gated on non-zero, and the JSON +
	 * defense_counters[] registrations repeat the bare counter tokens as
	 * narrative, so `grep -c arena_ptr_stale_caught_arg out.log` counts
	 * occurrences rather than the counter itself -- the same triage trap
	 * post_handler_corrupt_ptr_cumulative was added to close.  Emit one
	 * line per window per counter (even at zero so trend tracking has a
	 * t=0 anchor) with a distinctive _cumulative suffix; operators can
	 * `grep <counter>_cumulative out.log | tail -1` for the current
	 * total or grep -c the suffix to count windows.
	 */
	output(0, "[main] arena_ptr_stale_caught_arg_cumulative=%lu\n",
	       shm->stats.arena_ptr_stale_caught_arg);
	output(0, "[main] arena_ptr_stale_caught_post_state_cumulative=%lu\n",
	       shm->stats.arena_ptr_stale_caught_post_state);
	if (shm->stats.sibling_mprotect_failed)
		stat_row("corruption", "sibling_mprotect_failed", shm->stats.sibling_mprotect_failed);
	{
		/* Per-field divergence-sentinel rows: one stat_row per
		 * non-zero field shard so the operator sees which
		 * monitored field actually drifted rather than a lumped
		 * headline number.  Names match the defense_counters[]
		 * registration above so periodic and end-of-run views
		 * align. */
		static const struct {
			enum sentinel_field field;
			const char *name;
		} divergence_sentinel_rows[] = {
			{ SF_UNAME_SYSNAME,	"divergence_sentinel_anomalies_sysname"   },
			{ SF_UNAME_RELEASE,	"divergence_sentinel_anomalies_release"   },
			{ SF_UNAME_VERSION,	"divergence_sentinel_anomalies_version"   },
			{ SF_UNAME_MACHINE,	"divergence_sentinel_anomalies_machine"   },
			{ SF_SYSINFO_TOTALRAM,	"divergence_sentinel_anomalies_totalram"  },
			{ SF_SYSINFO_TOTALSWAP,	"divergence_sentinel_anomalies_totalswap" },
			{ SF_SYSINFO_TOTALHIGH,	"divergence_sentinel_anomalies_totalhigh" },
			{ SF_SYSINFO_MEM_UNIT,	"divergence_sentinel_anomalies_mem_unit"  },
		};
		unsigned int s;

		for (s = 0; s < ARRAY_SIZE(divergence_sentinel_rows); s++) {
			enum sentinel_field f = divergence_sentinel_rows[s].field;
			unsigned long v = shm->stats.divergence_sentinel_anomalies[f];

			if (v == 0)
				continue;
			stat_row("corruption",
				 divergence_sentinel_rows[s].name, v);
		}
	}
	if (shm->stats.divergence_sentinel_expected_drift)
		stat_row("corruption", "divergence_sentinel_expected_drift",
			 shm->stats.divergence_sentinel_expected_drift);
	if (shm->stats.destroy_object_idx_corrupt)
		stat_row("corruption", "destroy_object_idx",     shm->stats.destroy_object_idx_corrupt);
	if (shm->stats.global_obj_uaf_caught)
		stat_row("corruption", "global_obj_uaf_caught",  shm->stats.global_obj_uaf_caught);
	if (shm->stats.maps_pool_draw_exhausted)
		stat_row("pool", "maps_pool_draw_exhausted",   shm->stats.maps_pool_draw_exhausted);
	if (shm->stats.maps_reject_pool_empty)
		stat_row("pool", "maps_reject_pool_empty",     shm->stats.maps_reject_pool_empty);
	if (shm->stats.maps_reject_bogus_obj_ptr)
		stat_row("pool", "maps_reject_bogus_obj_ptr",  shm->stats.maps_reject_bogus_obj_ptr);
	if (shm->stats.maps_reject_alloc_track_miss)
		stat_row("pool", "maps_reject_alloc_track_miss", shm->stats.maps_reject_alloc_track_miss);
	if (shm->stats.maps_reject_alloc_track_miss_anon)
		stat_row("pool", "maps_reject_alloc_track_miss_anon",
			 shm->stats.maps_reject_alloc_track_miss_anon);
	if (shm->stats.maps_reject_alloc_track_miss_file)
		stat_row("pool", "maps_reject_alloc_track_miss_file",
			 shm->stats.maps_reject_alloc_track_miss_file);
	if (shm->stats.maps_reject_alloc_track_miss_testfile)
		stat_row("pool", "maps_reject_alloc_track_miss_testfile",
			 shm->stats.maps_reject_alloc_track_miss_testfile);
	if (shm->stats.maps_reject_size_zero)
		stat_row("pool", "maps_reject_size_zero",      shm->stats.maps_reject_size_zero);
	if (shm->stats.maps_reject_size_too_large)
		stat_row("pool", "maps_reject_size_too_large", shm->stats.maps_reject_size_too_large);
	if (shm->stats.chain_replay_len_corrupt)
		stat_row("corruption", "chain_replay_len_corrupt", shm->stats.chain_replay_len_corrupt);
	if (shm->stats.pagecache_canary_corrupt_caught)
		stat_row("oracle", "pagecache_canary_corrupt_caught",
			 shm->stats.pagecache_canary_corrupt_caught);
	if (shm->stats.objpool_array_stale_caught)
		stat_row("corruption", "objpool_array_stale_caught",
			 shm->stats.objpool_array_stale_caught);

	/* Derived ratio: avg get_map_handle() retry-loop attempts per
	 * successful pick.  The counter-pair comment in include/stats.h
	 * documents this as the realised cost the 1000-iter retry budget
	 * exists to amortise -- a value approaching the budget means the
	 * loop is dominated by the reject path and the side-index work is
	 * justified.  Rendered separately for the general get_map_handle()
	 * path and the get_map_with_prot() outer prot-filter retry, since
	 * the prot filter compounds prot reject on top of pool-pick reject
	 * and carries a different cost curve.  Skipped when the success
	 * denominator is zero. */
	{
		unsigned long s  = shm->stats.maps_pick_successes;
		unsigned long a  = shm->stats.maps_pick_attempts_sum;
		unsigned long ps = shm->stats.maps_pick_with_prot_successes;
		unsigned long pa = shm->stats.maps_pick_with_prot_attempts_sum;
		char val[32];

		if (s > 0) {
			unsigned long milli = ((a % s) * 1000UL) / s;

			snprintf(val, sizeof(val), "%lu.%03lu", a / s, milli);
			output(0, STATS_HDR_FMT, "pool",
			       "maps_pick_attempts_per_success", val);
		}
		if (ps > 0) {
			unsigned long milli = ((pa % ps) * 1000UL) / ps;

			snprintf(val, sizeof(val), "%lu.%03lu",
				 pa / ps, milli);
			output(0, STATS_HDR_FMT, "pool",
			       "maps_pick_with_prot_attempts_per_success",
			       val);
		}
	}
}

void dump_stats_childop_ranked_tables(void)
{
	{
		unsigned int op;
		char metric[40];

		for (op = 0; op < NR_CHILD_OP_TYPES; op++) {
			if (shm->stats.taint_transitions[op] == 0)
				continue;
			snprintf(metric, sizeof(metric), "%s",
				 alt_op_name((enum child_op_type)op));
			stat_row("taint_transitions", metric,
				 shm->stats.taint_transitions[op]);
		}

		for (op = 0; op < NR_CHILD_OP_TYPES; op++) {
			if (shm->stats.pool_race_aborted[op] == 0)
				continue;
			snprintf(metric, sizeof(metric), "%s",
				 alt_op_name((enum child_op_type)op));
			stat_row("pool_race_aborted", metric,
				 shm->stats.pool_race_aborted[op]);
		}

		/* Per-childop edge-discovery attribution: rendered sorted by
		 * count descending so the operator sees the dominant alt-op
		 * coverage contributors first.  CHILD_OP_SYSCALL is skipped
		 * because the syscall path attributes its edges via the
		 * explorer/bandit strategy counters; including it here would
		 * double-count against KCOV total. */
		{
			struct { unsigned int op; unsigned long count; }
				ranked[NR_CHILD_OP_TYPES];
			unsigned int nranked = 0, ri, rj;

			for (op = CHILD_OP_SYSCALL + 1;
			     op < NR_CHILD_OP_TYPES; op++) {
				unsigned long v =
					shm->stats.childop_edges_discovered[op];
				if (v == 0)
					continue;
				ranked[nranked].op = op;
				ranked[nranked].count = v;
				nranked++;
			}
			for (ri = 1; ri < nranked; ri++) {
				for (rj = ri; rj > 0 &&
				     ranked[rj].count > ranked[rj - 1].count;
				     rj--) {
					unsigned int to = ranked[rj].op;
					unsigned long tc = ranked[rj].count;
					ranked[rj] = ranked[rj - 1];
					ranked[rj - 1].op = to;
					ranked[rj - 1].count = tc;
				}
			}
			for (ri = 0; ri < nranked; ri++) {
				snprintf(metric, sizeof(metric), "%s",
					 alt_op_name((enum child_op_type)ranked[ri].op));
				stat_row("childop_edges_discovered",
					 metric, ranked[ri].count);
			}
		}

		/* Per-childop NEW-EDGE-CALL count: parallel ranked dump
		 * to childop_edges_discovered above so the operator can
		 * see both the edge total (above) and the productive-call
		 * count (here) side-by-side.  Same edge/call mismatch
		 * matters for the plateau classifier's Rule 2 ratio --
		 * the call counter here is the apples-to-apples
		 * comparator against the syscall-path bandit/explorer
		 * call counters. */
		{
			struct { unsigned int op; unsigned long count; }
				ranked[NR_CHILD_OP_TYPES];
			unsigned int nranked = 0, ri, rj;

			for (op = CHILD_OP_SYSCALL + 1;
			     op < NR_CHILD_OP_TYPES; op++) {
				unsigned long v =
					shm->stats.childop_calls_with_edges[op];
				if (v == 0)
					continue;
				ranked[nranked].op = op;
				ranked[nranked].count = v;
				nranked++;
			}
			for (ri = 1; ri < nranked; ri++) {
				for (rj = ri; rj > 0 &&
				     ranked[rj].count > ranked[rj - 1].count;
				     rj--) {
					unsigned int to = ranked[rj].op;
					unsigned long tc = ranked[rj].count;
					ranked[rj] = ranked[rj - 1];
					ranked[rj - 1].op = to;
					ranked[rj - 1].count = tc;
				}
			}
			for (ri = 0; ri < nranked; ri++) {
				snprintf(metric, sizeof(metric), "%s",
					 alt_op_name((enum child_op_type)ranked[ri].op));
				stat_row("childop_calls_with_edges",
					 metric, ranked[ri].count);
			}
		}

		/* Per-childop "last successful dispatch" fleet-clock
		 * timestamp, rendered alongside the per-op edge / call
		 * tables above so the operator sees calls, productive
		 * calls, and last-success-ts side-by-side per op.  Sorted
		 * by timestamp descending -- the most recently active op
		 * lands first, the oldest survivors trail it, and ops
		 * whose stamp is far behind shm_published->fleet_op_count
		 * are the dormancy candidates.  0 means "never
		 * succeeded" and is skipped (rendered as absent), matching
		 * the skip-zero convention in the two ranked dumps above.
		 * CHILD_OP_SYSCALL is skipped for the same reason as the
		 * sibling tables: the syscall path attributes its own
		 * activity via parent_stats.op_count / strategy counters
		 * and never bumps the per-childop arrays. */
		{
			struct { unsigned int op; unsigned long count; }
				ranked[NR_CHILD_OP_TYPES];
			unsigned int nranked = 0, ri, rj;

			for (op = CHILD_OP_SYSCALL + 1;
			     op < NR_CHILD_OP_TYPES; op++) {
				unsigned long v =
					shm->stats.childop_last_success_ts[op];
				if (v == 0)
					continue;
				ranked[nranked].op = op;
				ranked[nranked].count = v;
				nranked++;
			}
			for (ri = 1; ri < nranked; ri++) {
				for (rj = ri; rj > 0 &&
				     ranked[rj].count > ranked[rj - 1].count;
				     rj--) {
					unsigned int to = ranked[rj].op;
					unsigned long tc = ranked[rj].count;
					ranked[rj] = ranked[rj - 1];
					ranked[rj - 1].op = to;
					ranked[rj - 1].count = tc;
				}
			}
			for (ri = 0; ri < nranked; ri++) {
				snprintf(metric, sizeof(metric), "%s",
					 alt_op_name((enum child_op_type)ranked[ri].op));
				stat_row("childop_last_success_ts",
					 metric, ranked[ri].count);
			}
		}

		/* Per-childop setup-accepted yield: counts invocations that
		 * cleared the childop's one-shot setup / capability /
		 * namespace probe and reached the ready-to-exercise point.
		 * Read alongside childop_invocations[] to compute the
		 * setup-yield ratio per op.  Stays at 0 until per-childop
		 * producers are wired; until then the per-op dump simply
		 * omits the row (skip-zero, matching the sibling tables).
		 * CHILD_OP_SYSCALL is skipped for the same reason as above. */
		{
			struct { unsigned int op; unsigned long count; }
				ranked[NR_CHILD_OP_TYPES];
			unsigned int nranked = 0, ri, rj;

			for (op = CHILD_OP_SYSCALL + 1;
			     op < NR_CHILD_OP_TYPES; op++) {
				unsigned long v =
					shm->stats.childop_setup_accepted[op];
				if (v == 0)
					continue;
				ranked[nranked].op = op;
				ranked[nranked].count = v;
				nranked++;
			}
			for (ri = 1; ri < nranked; ri++) {
				for (rj = ri; rj > 0 &&
				     ranked[rj].count > ranked[rj - 1].count;
				     rj--) {
					unsigned int to = ranked[rj].op;
					unsigned long tc = ranked[rj].count;
					ranked[rj] = ranked[rj - 1];
					ranked[rj - 1].op = to;
					ranked[rj - 1].count = tc;
				}
			}
			for (ri = 0; ri < nranked; ri++) {
				snprintf(metric, sizeof(metric), "%s",
					 alt_op_name((enum child_op_type)ranked[ri].op));
				stat_row("childop_setup_accepted",
					 metric, ranked[ri].count);
			}
		}

		/* Per-childop data-path entry count: counts invocations that
		 * crossed from setup into the kernel-facing data path.
		 * setup_accepted - data_path is the count of invocations
		 * that accepted setup but bailed before exercising the
		 * kernel.  Stays at 0 until per-childop producers are wired.
		 * CHILD_OP_SYSCALL is skipped for the same reason as above. */
		{
			struct { unsigned int op; unsigned long count; }
				ranked[NR_CHILD_OP_TYPES];
			unsigned int nranked = 0, ri, rj;

			for (op = CHILD_OP_SYSCALL + 1;
			     op < NR_CHILD_OP_TYPES; op++) {
				unsigned long v =
					shm->stats.childop_data_path[op];
				if (v == 0)
					continue;
				ranked[nranked].op = op;
				ranked[nranked].count = v;
				nranked++;
			}
			for (ri = 1; ri < nranked; ri++) {
				for (rj = ri; rj > 0 &&
				     ranked[rj].count > ranked[rj - 1].count;
				     rj--) {
					unsigned int to = ranked[rj].op;
					unsigned long tc = ranked[rj].count;
					ranked[rj] = ranked[rj - 1];
					ranked[rj - 1].op = to;
					ranked[rj - 1].count = tc;
				}
			}
			for (ri = 0; ri < nranked; ri++) {
				snprintf(metric, sizeof(metric), "%s",
					 alt_op_name((enum child_op_type)ranked[ri].op));
				stat_row("childop_data_path",
					 metric, ranked[ri].count);
			}
		}

		/* Per-childop setup-bound scorecard: for ops that were
		 * invoked at all, rank ASCENDING by the setup-yield ratio
		 * setup_accepted / invocations, rendered as a permille
		 * (0..1000) integer to avoid float in the stats path.  A
		 * low ratio means many invocations bailed before clearing
		 * setup -- those ops want environment / capability / probe
		 * attention.  Skip-zero is implicit via the
		 * childop_invocations[op] > 0 filter, which also guards
		 * the divide.  CHILD_OP_SYSCALL is skipped for the same
		 * reason as the sibling tables. */
		{
			struct { unsigned int op; unsigned long ratio; }
				ranked[NR_CHILD_OP_TYPES];
			unsigned int nranked = 0, ri, rj;

			for (op = CHILD_OP_SYSCALL + 1;
			     op < NR_CHILD_OP_TYPES; op++) {
				unsigned long inv =
					shm->stats.childop_invocations[op];
				unsigned long acc;

				if (inv == 0)
					continue;
				acc = shm->stats.childop_setup_accepted[op];
				ranked[nranked].op = op;
				ranked[nranked].ratio = acc * 1000UL / inv;
				nranked++;
			}
			for (ri = 1; ri < nranked; ri++) {
				for (rj = ri; rj > 0 &&
				     ranked[rj].ratio < ranked[rj - 1].ratio;
				     rj--) {
					unsigned int to = ranked[rj].op;
					unsigned long tr = ranked[rj].ratio;
					ranked[rj] = ranked[rj - 1];
					ranked[rj - 1].op = to;
					ranked[rj - 1].ratio = tr;
				}
			}
			for (ri = 0; ri < nranked; ri++) {
				unsigned long r = ranked[ri].ratio;

				/* Some childops bump setup_accepted more than
				 * once per dispatch, so acc can exceed inv and
				 * the raw ratio can exceed 1000.  Clamp at the
				 * render site to preserve the documented
				 * 0..1000 permille invariant; the ordering
				 * across over-the-cap ops is not meaningful
				 * (they are all "setup never bailed"). */
				if (r > 1000UL)
					r = 1000UL;
				snprintf(metric, sizeof(metric), "%s",
					 alt_op_name((enum child_op_type)ranked[ri].op));
				stat_row("childop_setup_bound_permille",
					 metric, r);
			}
		}

		/* Per-childop data-path-cold scorecard: for ops that
		 * reached the kernel data path at all, rank ASCENDING by
		 * calls_with_edges / data_path, rendered as a permille
		 * (0..1000) integer to avoid float in the stats path.  A
		 * low ratio means many kernel-facing calls but no new
		 * edges -- those ops want generator / state work or
		 * demotion.  Skip-zero is implicit via the
		 * childop_data_path[op] > 0 filter, which also guards the
		 * divide.  CHILD_OP_SYSCALL is skipped for the same
		 * reason as the sibling tables. */
		{
			struct { unsigned int op; unsigned long ratio; }
				ranked[NR_CHILD_OP_TYPES];
			unsigned int nranked = 0, ri, rj;

			for (op = CHILD_OP_SYSCALL + 1;
			     op < NR_CHILD_OP_TYPES; op++) {
				unsigned long dp =
					shm->stats.childop_data_path[op];
				unsigned long ce;

				if (dp == 0)
					continue;
				ce = shm->stats.childop_calls_with_edges[op];
				ranked[nranked].op = op;
				ranked[nranked].ratio = ce * 1000UL / dp;
				nranked++;
			}
			for (ri = 1; ri < nranked; ri++) {
				for (rj = ri; rj > 0 &&
				     ranked[rj].ratio < ranked[rj - 1].ratio;
				     rj--) {
					unsigned int to = ranked[rj].op;
					unsigned long tr = ranked[rj].ratio;
					ranked[rj] = ranked[rj - 1];
					ranked[rj - 1].op = to;
					ranked[rj - 1].ratio = tr;
				}
			}
			for (ri = 0; ri < nranked; ri++) {
				snprintf(metric, sizeof(metric), "%s",
					 alt_op_name((enum child_op_type)ranked[ri].op));
				stat_row("childop_data_path_cold_permille",
					 metric, ranked[ri].ratio);
			}
		}

		/* Per-childop missing Step-B yield producer map: emit a row
		 * for each op that has been dispatched at least once but
		 * still has no setup-accepted producer wired -- i.e.
		 * childop_invocations[op] > 0 AND
		 * childop_setup_accepted[op] == 0.  These are the ops that
		 * silently skip the setup/data-path scorecards because no
		 * Step-B producer is bumping setup_accepted on the hot path.
		 * The value rendered is the invocations count so the
		 * operator can see how much dispatch pressure the missing
		 * producer is masking.  Self-maintains as Step-B producers
		 * land: rows disappear once setup_accepted[op] starts
		 * moving.  CHILD_OP_SYSCALL is skipped for the same reason
		 * as the sibling tables. */
		for (op = CHILD_OP_SYSCALL + 1;
		     op < NR_CHILD_OP_TYPES; op++) {
			unsigned long inv =
				shm->stats.childop_invocations[op];
			if (inv == 0)
				continue;
			if (shm->stats.childop_setup_accepted[op] != 0)
				continue;
			snprintf(metric, sizeof(metric), "%s",
				 alt_op_name((enum child_op_type)op));
			stat_row("childop_missing_producer", metric, inv);
		}

		/* Per-childop one-shot latch reason: rendered as the integer
		 * enum childop_latch_reason code (see include/child.h).  No
		 * string table is materialised at the dump layer -- the
		 * operator decodes.  0 (CHILDOP_LATCH_NONE) is skipped so
		 * the per-op dump only emits rows for ops that actually
		 * latched themselves off.  CHILD_OP_SYSCALL is skipped for
		 * the same reason as above. */
		for (op = CHILD_OP_SYSCALL + 1;
		     op < NR_CHILD_OP_TYPES; op++) {
			unsigned long v =
				shm->stats.childop_latch_reason[op];
			if (v == 0)
				continue;
			snprintf(metric, sizeof(metric), "%s",
				 alt_op_name((enum child_op_type)op));
			stat_row("childop_latch_reason", metric, v);
		}

		/* SHADOW score-driven recommendation counters bumped from
		 * close_window_and_decide() in child-canary.c.  Divergence
		 * between these and the live promote/demote count
		 * (canary_op_state.total_demotions / total_promotions, surfaced
		 * via canary_queue_summary()) is the signal the 75.2.B
		 * enforcement work needs before it can take over the picker;
		 * surfacing them here keeps the dump self-contained.  Skip-
		 * zero, CHILD_OP_SYSCALL-skipped (matches the surrounding
		 * per-childop arrays). */
		for (op = CHILD_OP_SYSCALL + 1;
		     op < NR_CHILD_OP_TYPES; op++) {
			unsigned long v =
				shm->stats.childop_would_demote[op];
			if (v == 0)
				continue;
			snprintf(metric, sizeof(metric), "%s",
				 alt_op_name((enum child_op_type)op));
			stat_row("childop_would_demote", metric, v);
		}
		for (op = CHILD_OP_SYSCALL + 1;
		     op < NR_CHILD_OP_TYPES; op++) {
			unsigned long v =
				shm->stats.childop_would_promote[op];
			if (v == 0)
				continue;
			snprintf(metric, sizeof(metric), "%s",
				 alt_op_name((enum child_op_type)op));
			stat_row("childop_would_promote", metric, v);
		}
	}
}

void dump_stats_strategy_summary(void)
{
	if (shm->stats.bandit_cmp_reward_added)
		stat_row("strategy", "bandit_cmp_reward_added",
			 shm->stats.bandit_cmp_reward_added);
	if (shm->stats.frontier_strategy_picks)
		stat_row("strategy", "frontier_strategy_picks",
			 shm->stats.frontier_strategy_picks);
	if (shm->stats.frontier_live_picks)
		stat_row("strategy", "frontier_live_picks",
			 shm->stats.frontier_live_picks);
	if (shm->stats.frontier_silent_picks)
		stat_row("strategy", "frontier_silent_picks",
			 shm->stats.frontier_silent_picks);
	/* SHADOW-ONLY observability companions to frontier_silent_picks:
	 * the candidate count (how many threshold-crossings the silent
	 * regime has produced) and the threshold itself, emitted side by
	 * side so the operator can interpret the count without consulting
	 * the source.  Neither value is read by the live picker math. */
	if (shm->stats.frontier_shadow_decay_candidates)
		stat_row("strategy", "frontier_shadow_decay_candidates",
			 shm->stats.frontier_shadow_decay_candidates);
	stat_row("strategy", "frontier_shadow_decay_streak_threshold",
		 FRONTIER_SHADOW_DECAY_STREAK);
	/* Tightened decay predicate (sibling of the looser counter above):
	 * adds the no-CMP-novelty + no-errno-shift UNLESS clause to the
	 * threshold-crossing test, and tallies the projected demote count
	 * across all silent-regime picks past the threshold.  The (looser
	 * candidates / candidates) ratio tells the operator what fraction
	 * of N-silent crossings the CMP/errno tightening would have spared;
	 * the would_skip / silent_picks ratio is the projected pick share a
	 * live silent-decay variant would demote. */
	if (shm->stats.frontier_decay_candidates)
		stat_row("strategy", "frontier_decay_candidates",
			 shm->stats.frontier_decay_candidates);
	if (shm->stats.frontier_decay_would_skip)
		stat_row("strategy", "frontier_decay_would_skip",
			 shm->stats.frontier_decay_would_skip);
	/* Arm-B-only live reject count for the silent-streak decay above.
	 * Pairs with frontier_decay_would_skip (both arms) as the headline
	 * arm-B behaviour delta; normalise against the Arm-B silent-pick
	 * throughput recoverable from frontier_silent_picks and the
	 * frontier_silent_decay_arm_{a,b}_children cohort split in kcov_shm. */
	if (shm->stats.frontier_silent_decay_live_rejects)
		stat_row("strategy", "frontier_silent_decay_live_rejects",
			 shm->stats.frontier_silent_decay_live_rejects);
	/* SHADOW-ONLY saturation-cooldown counters.  Gated by
	 * --frontier-saturation-cooldown != off; zero on default-off runs
	 * so the rows stay suppressed by the if-non-zero guard.  Read the
	 * (would_skip / candidates) ratio for the spare-lane catch rate and
	 * the per-syscall frontier_satcool_would_skip_per_syscall[] top-N
	 * (rendered by dump_satcool_would_skip_per_syscall_top() below) to
	 * confirm the demote mass concentrates on syncfs / sendfile /
	 * semget / writev and is ~0 on removexattrat / futex /
	 * io_uring_setup / bpf before tuning C_min or wiring the COMBINED
	 * reject. */
	if (shm->stats.frontier_satcool_candidates)
		stat_row("strategy", "frontier_satcool_candidates",
			 shm->stats.frontier_satcool_candidates);
	if (shm->stats.frontier_satcool_would_skip)
		stat_row("strategy", "frontier_satcool_would_skip",
			 shm->stats.frontier_satcool_would_skip);
	if (shm->stats.frontier_satcool_spared_arggen)
		stat_row("strategy", "frontier_satcool_spared_arggen",
			 shm->stats.frontier_satcool_spared_arggen);
	if (shm->stats.frontier_satcool_spared_objproducer)
		stat_row("strategy", "frontier_satcool_spared_objproducer",
			 shm->stats.frontier_satcool_spared_objproducer);
	dump_satcool_would_skip_per_syscall_top();
	/* SHADOW-ONLY LIVE-regime cooldown projections.  Sibling block to
	 * the silent-streak decay rows above: candidates is the distinct
	 * cooldown-episode count (one bump per FRONTIER_LIVE_MISS_COOLDOWN
	 * crossing per syscall); would_skip is the projected demote count a
	 * live cooldown variant of the picker would produce, normalised
	 * against frontier_live_picks for the projected reclaim fraction.
	 * The threshold is emitted alongside so the operator can interpret
	 * the candidate count without consulting the source, matching the
	 * frontier_shadow_decay_streak_threshold row above. */
	if (shm->stats.frontier_live_cooldown_candidates)
		stat_row("strategy", "frontier_live_cooldown_candidates",
			 shm->stats.frontier_live_cooldown_candidates);
	if (shm->stats.frontier_live_would_skip)
		stat_row("strategy", "frontier_live_would_skip",
			 shm->stats.frontier_live_would_skip);
	stat_row("strategy", "frontier_live_miss_cooldown_threshold",
		 FRONTIER_LIVE_MISS_COOLDOWN);
	dump_live_cooldown_would_skip_per_syscall_top();
	/* SHADOW-ONLY LIVE-regime cooldown discriminator (gated by
	 * --frontier-live-cooldown-mode != off).  Sibling block to the
	 * undiscriminated frontier_live_cooldown_candidates / frontier_
	 * live_would_skip rows above; this row projects the DISCRIMINATED
	 * LIVE-regime demote mass after the spare lanes peel productive
	 * syscalls out of the cool set.  Compare (live_cool_would_skip /
	 * live_would_skip) for the over-cool fraction the discriminator
	 * removes.  The low live floor (FRONTIER_LIVE_COOL_CMIN) is
	 * emitted alongside so the operator can interpret the candidate
	 * count without consulting the source, matching the
	 * frontier_live_miss_cooldown_threshold row above. */
	if (shm->stats.frontier_live_cool_candidates)
		stat_row("strategy", "frontier_live_cool_candidates",
			 shm->stats.frontier_live_cool_candidates);
	if (shm->stats.frontier_live_cool_would_skip)
		stat_row("strategy", "frontier_live_cool_would_skip",
			 shm->stats.frontier_live_cool_would_skip);
	if (shm->stats.frontier_live_cool_spared_windowed)
		stat_row("strategy", "frontier_live_cool_spared_windowed",
			 shm->stats.frontier_live_cool_spared_windowed);
	if (shm->stats.frontier_live_cool_spared_arggen)
		stat_row("strategy", "frontier_live_cool_spared_arggen",
			 shm->stats.frontier_live_cool_spared_arggen);
	if (shm->stats.frontier_live_cool_spared_objproducer)
		stat_row("strategy", "frontier_live_cool_spared_objproducer",
			 shm->stats.frontier_live_cool_spared_objproducer);
	/* Threshold companion to the scalar rows above.  Gated on the
	 * discriminator mode rather than emitted unconditionally so a
	 * default-off run does not grow a new stats row (the cmin
	 * threshold is meaningful only when the discriminator is
	 * actually evaluating); the sibling dump_live_cool_per_syscall_
	 * top calls below already mode-OFF-early-return for the same
	 * default-identity contract.  Sibling rows like frontier_live_
	 * miss_cooldown_threshold above stay unconditional because
	 * their counters predate this discriminator's mode flag. */
	if (__atomic_load_n(&frontier_live_cooldown_mode,
			    __ATOMIC_RELAXED) !=
	    FRONTIER_LIVE_COOLDOWN_MODE_OFF)
		stat_row("strategy", "frontier_live_cool_cmin",
			 FRONTIER_LIVE_COOL_CMIN);
	dump_live_cool_per_syscall_top(
		shm->stats.frontier_live_cool_would_skip_per_syscall,
		"frontier_live_cool_would_skip");
	dump_live_cool_per_syscall_top(
		shm->stats.frontier_live_cool_would_spare_per_syscall,
		"frontier_live_cool_would_spare");
	/* Did-decay observability counter for the LIVE-regime early ring-
	 * decay path.  One bump per (nr, rotation) where the early ring-
	 * decay halved a non-zero cached sum.  Read alongside
	 * frontier_live_would_skip (F3 projection) to compare the projected
	 * vs the actually-applied cooldown volume; the ratio reflects how
	 * often the rotation-time decay catches a syscall the per-pick F3
	 * projection had already counted as a candidate. */
	if (shm->stats.frontier_live_cooldown_decays)
		stat_row("strategy", "frontier_live_cooldown_decays",
			 shm->stats.frontier_live_cooldown_decays);
	/* Blanket LIVE-regime probabilistic pick-reject (safe down-
	 * payment).  Reclaims ~1 / FRONTIER_LIVE_DECAY_REJECT_DENOM of
	 * LIVE-ring picks unconditionally; the reject rate against
	 * accepted picks is rejects / (rejects + frontier_live_picks)
	 * and should converge to 1 / REJECT_DENOM.  Read alongside
	 * frontier_live_would_skip (the F3 SHADOW projection) to gauge
	 * the headroom a targeted variant of this reject would unlock. */
	if (shm->stats.frontier_live_decay_live_rejects)
		stat_row("strategy", "frontier_live_decay_live_rejects",
			 shm->stats.frontier_live_decay_live_rejects);
	/* SHADOW + per-child A/B errno-plateau decay (silent-regime accept
	 * site): would_skip is the both-arms shadow demote count, live_
	 * rejects is the arm-B-only actual demote count, overlap_silent is
	 * the both-arms shadow count of picks where the consecutive-silent
	 * shadow predicate ALSO fires.  Emitted side by side with the
	 * silent-streak shadow rows above so the operator can read the
	 * orthogonal coverage (would_skip - overlap_silent) at a glance. */
	if (shm->stats.frontier_errno_decay_would_skip)
		stat_row("strategy", "frontier_errno_decay_would_skip",
			 shm->stats.frontier_errno_decay_would_skip);
	if (shm->stats.frontier_errno_decay_live_rejects)
		stat_row("strategy", "frontier_errno_decay_live_rejects",
			 shm->stats.frontier_errno_decay_live_rejects);
	if (shm->stats.frontier_errno_decay_overlap_silent)
		stat_row("strategy", "frontier_errno_decay_overlap_silent",
			 shm->stats.frontier_errno_decay_overlap_silent);
	/* SHADOW-ONLY A/B scoring for the frontier-blend cold-weight
	 * blend.  Emitted as a sibling block to the silent-decay shadow
	 * counters above; the picker still consumes the OLD weight from
	 * frontier_cold_weight() and these counters expose how often the
	 * blended formula would have steered differently.  See the
	 * struct-field comments in include/stats.h for semantics. */
	if (shm->stats.frontier_blend_samples) {
		stat_row("strategy", "frontier_blend_samples",
			 shm->stats.frontier_blend_samples);
		stat_row("strategy", "frontier_blend_new_lower",
			 shm->stats.frontier_blend_new_lower);
		stat_row("strategy", "frontier_blend_new_higher",
			 shm->stats.frontier_blend_new_higher);
		stat_row("strategy", "frontier_blend_new_equal",
			 shm->stats.frontier_blend_new_equal);
		stat_row("strategy", "frontier_blend_old_weight_sum",
			 shm->stats.frontier_blend_old_weight_sum);
		stat_row("strategy", "frontier_blend_new_weight_sum",
			 shm->stats.frontier_blend_new_weight_sum);
	}
	/* Per-band shadow counters for --reach-band.  Sibling of the
	 * frontier_blend_* block above.  Silent on default (OFF) runs --
	 * the gate in frontier_cold_weight() early-outs before the bumps,
	 * so the per-band picks array stays at zero and the if-guard
	 * suppresses the whole block.  See the reach_band_* field-comment
	 * block in include/stats.h for the SHADOW_ONLY vs COMBINED reading
	 * of would_demote_mid / would_boost_high. */
	if (shm->stats.reach_band_picks_per_band[REACH_BAND_IDX_LOW] ||
	    shm->stats.reach_band_picks_per_band[REACH_BAND_IDX_MID] ||
	    shm->stats.reach_band_picks_per_band[REACH_BAND_IDX_HIGH]) {
		stat_row("strategy", "reach_band_picks_low",
			 shm->stats.reach_band_picks_per_band[REACH_BAND_IDX_LOW]);
		stat_row("strategy", "reach_band_picks_mid",
			 shm->stats.reach_band_picks_per_band[REACH_BAND_IDX_MID]);
		stat_row("strategy", "reach_band_picks_high",
			 shm->stats.reach_band_picks_per_band[REACH_BAND_IDX_HIGH]);
		stat_row("strategy", "reach_band_would_demote_mid",
			 shm->stats.reach_band_would_demote_mid);
		stat_row("strategy", "reach_band_would_boost_high",
			 shm->stats.reach_band_would_boost_high);
	}
	/* Adaptive expensive-syscall accept gate.  All zero while the
	 * gate is in its default OFF mode (the early-return path skips
	 * the bumps).  See the expensive_adaptive_* field-comment block
	 * in include/stats.h for per-counter semantics. */
	if (shm->stats.expensive_adaptive_samples) {
		stat_row("strategy", "expensive_adaptive_samples",
			 shm->stats.expensive_adaptive_samples);
		stat_row("strategy", "expensive_adaptive_extra_accepts",
			 shm->stats.expensive_adaptive_extra_accepts);
		stat_row("strategy", "expensive_adaptive_demotes",
			 shm->stats.expensive_adaptive_demotes);
	}
	/* Object-size-relative ARG_LEN draw observability.  The gate scalar
	 * arg_len_semantics_draws stays zero while --arg-len-semantics is
	 * off (the default), so the whole block is silent on baseline
	 * runs.  See the struct-field comment in include/stats.h. */
	if (shm->stats.arg_len_semantics_draws) {
		stat_row("strategy", "arg_len_semantics_draws",
			 shm->stats.arg_len_semantics_draws);
		stat_row("strategy", "arg_len_objrelative_used",
			 shm->stats.arg_len_objrelative_used);
		stat_row("strategy", "arg_len_objrelative_nosize",
			 shm->stats.arg_len_objrelative_nosize);
		stat_row("strategy", "arg_len_objrel_blend_getlen",
			 shm->stats.arg_len_objrel_blend_getlen);
		stat_row("strategy", "arg_len_objrel_zero",
			 shm->stats.arg_len_objrel_zero);
		stat_row("strategy", "arg_len_objrel_one",
			 shm->stats.arg_len_objrel_one);
		stat_row("strategy", "arg_len_objrel_objsize",
			 shm->stats.arg_len_objrel_objsize);
		stat_row("strategy", "arg_len_objrel_objsize_minus_1",
			 shm->stats.arg_len_objrel_objsize_minus_1);
		stat_row("strategy", "arg_len_objrel_objsize_half",
			 shm->stats.arg_len_objrel_objsize_half);
		stat_row("strategy", "arg_len_objrel_pagesize",
			 shm->stats.arg_len_objrel_pagesize);
		stat_row("strategy", "arg_len_objrel_pagesize_plus_1",
			 shm->stats.arg_len_objrel_pagesize_plus_1);
		stat_row("strategy", "arg_len_objrel_pagesize_minus_1",
			 shm->stats.arg_len_objrel_pagesize_minus_1);
	}
	if (shm->stats.frontier_underflow_prevented)
		stat_row("strategy", "frontier_underflow_prevented",
			 shm->stats.frontier_underflow_prevented);
	if (shm->stats.frontier_intervention_pulls)
		stat_row("strategy", "frontier_intervention_pulls",
			 shm->stats.frontier_intervention_pulls);
	if (shm->stats.frontier_intervention_cold_skipped)
		stat_row("strategy", "frontier_intervention_cold_skipped",
			 shm->stats.frontier_intervention_cold_skipped);
	if (shm->stats.plateau_forced_windows)
		stat_row("strategy", "plateau_forced_windows",
			 shm->stats.plateau_forced_windows);
	/* SHADOW-ONLY wall-lever.  eligible_total / would_suppress_
	 * total expose the data-driven gate's projected reclaim share on every
	 * plateau-active pick; baseline_calls is the fleet mean per_syscall_
	 * calls the predicate scaled WALL_LEVER_HIGH_MULT against.  See the
	 * struct-field comment in include/stats.h. */
	if (shm->stats.wall_lever_eligible_total) {
		stat_row("strategy", "wall_lever_eligible_total",
			 shm->stats.wall_lever_eligible_total);
		stat_row("strategy", "wall_lever_would_suppress_total",
			 shm->stats.wall_lever_would_suppress_total);
		stat_row("strategy", "wall_lever_baseline_calls",
			 __atomic_load_n(&shm->wall_lever_baseline_calls,
					 __ATOMIC_RELAXED));

		/* Top-N per-syscall would-suppress breakdown.  The aggregate
		 * total above is the headline reclaim projection a live
		 * variant would produce; this block exposes WHICH syscalls
		 * the projection is attributable to, so the budget can be
		 * audited by-syscall (against the existing top edge / pick
		 * blocks) BEFORE any live suppression is enabled.  Mirrors
		 * the absolute-totals top-N shape and biarch table choice
		 * the per-syscall edge top-N in dump_stats() already uses:
		 * under biarch only the 64-bit table is iterated -- 32-bit
		 * nrs collide with 64-bit ones in the same index space and
		 * would shadow them in the display. */
		{
			unsigned int top_nr[TOP_SYSCALLS_DUMP_TOPN];
			unsigned long top_vals[TOP_SYSCALLS_DUMP_TOPN];
			unsigned int top_count = 0;
			unsigned int nr_to_scan;
			const struct syscalltable *table;
			unsigned int i;
			int j;

			if (biarch) {
				nr_to_scan = max_nr_64bit_syscalls;
				table = syscalls_64bit;
			} else {
				nr_to_scan = max_nr_syscalls;
				table = syscalls;
			}
			if (nr_to_scan > MAX_NR_SYSCALL)
				nr_to_scan = MAX_NR_SYSCALL;

			memset(top_vals, 0, sizeof(top_vals));
			for (i = 0; i < nr_to_scan; i++) {
				unsigned long v = __atomic_load_n(
					&shm->stats.wall_lever_would_suppress[i],
					__ATOMIC_RELAXED);

				if (v == 0)
					continue;
				topn_push(top_vals, top_nr, &top_count,
					  TOP_SYSCALLS_DUMP_TOPN, v, i);
			}

			if (top_count > 0) {
				output(0, "Top wall-lever would-suppress "
					  "syscalls (shadow-only):\n");
				for (j = 0; j < (int)top_count; j++) {
					struct syscallentry *entry =
						table[top_nr[j]].entry;
					const char *name = entry ? entry->name
								 : "???";

					output(0, "  %-24s %lu\n",
					       name, top_vals[j]);
				}
			}
		}
	}
	/* Unconditional wall-lever would-suppress observability.  The
	 * sibling block above only renders when the predicate has
	 * registered at least one eligible pick (wall_lever_eligible_total
	 * != 0); this block surfaces the running would-suppress total and
	 * its top-N per-syscall breakdown on EVERY dump so the projected
	 * reclaim share + by-syscall attribution stay visible on runs
	 * where the eligibility gate has not triggered yet.  Skip-zero on
	 * the per-syscall scan + a top_count guard on the header suppress
	 * the empty top-N; the scalar total renders unconditionally so a
	 * 0 is an active "nothing accumulated" signal rather than silence.
	 * Mirrors the biarch table choice + topn_push idiom used above. */
	stat_row("strategy", "wall_lever_would_suppress_total",
		 shm->stats.wall_lever_would_suppress_total);
	{
		unsigned int top_nr[TOP_SYSCALLS_DUMP_TOPN];
		unsigned long top_vals[TOP_SYSCALLS_DUMP_TOPN];
		unsigned int top_count = 0;
		unsigned int nr_to_scan;
		const struct syscalltable *table;
		unsigned int i;
		int j;

		if (biarch) {
			nr_to_scan = max_nr_64bit_syscalls;
			table = syscalls_64bit;
		} else {
			nr_to_scan = max_nr_syscalls;
			table = syscalls;
		}
		if (nr_to_scan > MAX_NR_SYSCALL)
			nr_to_scan = MAX_NR_SYSCALL;

		memset(top_vals, 0, sizeof(top_vals));
		for (i = 0; i < nr_to_scan; i++) {
			unsigned long v = __atomic_load_n(
				&shm->stats.wall_lever_would_suppress[i],
				__ATOMIC_RELAXED);

			if (v == 0)
				continue;
			topn_push(top_vals, top_nr, &top_count,
				  TOP_SYSCALLS_DUMP_TOPN, v, i);
		}

		if (top_count > 0) {
			output(0, "Top wall-lever would-suppress "
				  "syscalls (running, shadow-only):\n");
			for (j = 0; j < (int)top_count; j++) {
				struct syscallentry *entry =
					table[top_nr[j]].entry;
				const char *name = entry ? entry->name
							 : "???";

				output(0, "  %-24s %lu\n",
				       name, top_vals[j]);
			}
		}
	}
	if (shm->stats.strategy_explorer_picks)
		stat_row("strategy", "strategy_explorer_picks",
			 shm->stats.strategy_explorer_picks);

	dump_strategy_stats();
}

void __cold dump_stats_childop_runs_network(void)
{
	stat_category_emit_text(&socket_family_chain_category);

	stat_category_emit_text(&socket_family_grammar_category);

	stat_category_emit_text(&tls_rotate_category);

	if (shm->stats.packet_fanout_runs) {
		stat_row("packet_fanout_thrash", "runs",             shm->stats.packet_fanout_runs);
		stat_row("packet_fanout_thrash", "setup_failed",     shm->stats.packet_fanout_setup_failed);
		stat_row("packet_fanout_thrash", "ring_failed",      shm->stats.packet_fanout_ring_failed);
		stat_row("packet_fanout_thrash", "rings_installed",  shm->stats.packet_fanout_rings_installed);
		stat_row("packet_fanout_thrash", "mmap_failed",      shm->stats.packet_fanout_mmap_failed);
		stat_row("packet_fanout_thrash", "joins",            shm->stats.packet_fanout_joins);
		stat_row("packet_fanout_thrash", "rejoins_ok",       shm->stats.packet_fanout_rejoins_ok);
		stat_row("packet_fanout_thrash", "rejoins_rejected", shm->stats.packet_fanout_rejoins_rejected);
	}

	if (shm->stats.eth_emitter_runs) {
		stat_row("eth_emitter", "runs",               shm->stats.eth_emitter_runs);
		stat_row("eth_emitter", "setup_failed",       shm->stats.eth_emitter_setup_failed);
		stat_row("eth_emitter", "short",              shm->stats.eth_emitter_short);
		stat_row("eth_emitter", "sends_ok",           shm->stats.eth_emitter_sends_ok);
		stat_row("eth_emitter", "sends_failed",       shm->stats.eth_emitter_sends_failed);
		stat_row("eth_emitter", "tmpl_arp",           shm->stats.eth_emitter_per_tmpl[0]);
		stat_row("eth_emitter", "tmpl_ipv4_frag_zero", shm->stats.eth_emitter_per_tmpl[1]);
		stat_row("eth_emitter", "tmpl_ipv6_na",       shm->stats.eth_emitter_per_tmpl[2]);
		stat_row("eth_emitter", "tmpl_vlan_qinq",     shm->stats.eth_emitter_per_tmpl[3]);
		stat_row("eth_emitter", "tmpl_bad_ethertype", shm->stats.eth_emitter_per_tmpl[4]);
	}

	if (shm->stats.iouring_multishot_runs) {
		stat_row("iouring_net_multishot", "runs",             shm->stats.iouring_multishot_runs);
		stat_row("iouring_net_multishot", "setup_failed",     shm->stats.iouring_multishot_setup_failed);
		stat_row("iouring_net_multishot", "pbuf_ring_ok",     shm->stats.iouring_multishot_pbuf_ring_ok);
		stat_row("iouring_net_multishot", "pbuf_legacy_ok",   shm->stats.iouring_multishot_pbuf_legacy_ok);
		stat_row("iouring_net_multishot", "armed",            shm->stats.iouring_multishot_armed);
		stat_row("iouring_net_multishot", "packets_sent",     shm->stats.iouring_multishot_packets_sent);
		stat_row("iouring_net_multishot", "completions",      shm->stats.iouring_multishot_completions);
		stat_row("iouring_net_multishot", "cancel_submitted", shm->stats.iouring_multishot_cancel_submitted);
		stat_row("iouring_net_multishot", "napi_register_ok",   shm->stats.iouring_napi_register_ok);
		stat_row("iouring_net_multishot", "napi_register_fail", shm->stats.iouring_napi_register_fail);
		stat_row("iouring_net_multishot", "napi_unregister_ok", shm->stats.iouring_napi_unregister_ok);
		stat_row("iouring_net_multishot", "napi_unregister_fail", shm->stats.iouring_napi_unregister_fail);
	}

	stat_category_emit_text(&tcp_ao_rotate_category);

	stat_category_emit_text(&tcp_md5_listener_race_category);

	stat_category_emit_text(&ipv6_pmtu_race_category);

	stat_category_emit_text(&vrf_fib_churn_category);

	stat_category_emit_text(&mpls_route_churn_category);

	stat_category_emit_text(&netlink_monitor_race_category);

	stat_category_emit_text(&tipc_link_churn_category);

	stat_category_emit_text(&tls_ulp_churn_category);

	stat_category_emit_text(&vxlan_encap_churn_category);

	stat_category_emit_text(&ovs_tunnel_vport_churn_category);

	if (shm->stats.bridge_fdb_stp_runs) {
		stat_row("bridge_fdb_stp", "runs",            shm->stats.bridge_fdb_stp_runs);
		stat_row("bridge_fdb_stp", "setup_failed",    shm->stats.bridge_fdb_stp_setup_failed);
		stat_row("bridge_fdb_stp", "bridge_create_ok", shm->stats.bridge_fdb_stp_bridge_create_ok);
		stat_row("bridge_fdb_stp", "veth_create_ok",  shm->stats.bridge_fdb_stp_veth_create_ok);
		stat_row("bridge_fdb_stp", "raw_send_ok",     shm->stats.bridge_fdb_stp_raw_send_ok);
		stat_row("bridge_fdb_stp", "stp_toggle_ok",   shm->stats.bridge_fdb_stp_stp_toggle_ok);
		stat_row("bridge_fdb_stp", "fdb_del_ok",      shm->stats.bridge_fdb_stp_fdb_del_ok);
		stat_row("bridge_fdb_stp", "link_del_ok",     shm->stats.bridge_fdb_stp_link_del_ok);
		stat_row("bridge_fdb_stp", "vlan_mass_runs",  shm->stats.bridge_vlan_mass_runs);
		stat_row("bridge_fdb_stp", "vlan_mass_max_n", shm->stats.bridge_vlan_mass_max_n);
		stat_row("bridge_fdb_stp", "vlan_mass_enotbufs", shm->stats.bridge_vlan_mass_enotbufs);
	}

	stat_category_emit_text(&bridge_conntrack_churn_category);

	if (shm->stats.nftables_churn_runs) {
		stat_row("nftables_churn", "runs",             shm->stats.nftables_churn_runs);
		stat_row("nftables_churn", "setup_failed",     shm->stats.nftables_churn_setup_failed);
		stat_row("nftables_churn", "table_create_ok",  shm->stats.nftables_churn_table_create_ok);
		stat_row("nftables_churn", "set_create_ok",    shm->stats.nftables_churn_set_create_ok);
		stat_row("nftables_churn", "chain_create_ok",  shm->stats.nftables_churn_chain_create_ok);
		stat_row("nftables_churn", "rule_create_ok",   shm->stats.nftables_churn_rule_create_ok);
		stat_row("nftables_churn", "packet_sent_ok",   shm->stats.nftables_churn_packet_sent_ok);
		stat_row("nftables_churn", "rule_insert_ok",   shm->stats.nftables_churn_rule_insert_ok);
		stat_row("nftables_churn", "rule_del_ok",      shm->stats.nftables_churn_rule_del_ok);
		stat_row("nftables_churn", "table_del_ok",     shm->stats.nftables_churn_table_del_ok);
		stat_row("nftables_churn", "payload_expr_emit",shm->stats.nftables_churn_payload_expr_emit);
		stat_row("nftables_churn", "objref_expr_emit", shm->stats.nftables_churn_objref_expr_emit);
		stat_row("nftables_churn", "compat_validate_install_ok",     shm->stats.nft_compat_validate_install_ok);
		stat_row("nftables_churn", "compat_validate_install_fail",   shm->stats.nft_compat_validate_install_fail);
		stat_row("nftables_churn", "compat_validate_unsupported",    shm->stats.nft_compat_validate_unsupported);
		stat_row("nftables_churn", "compat_validate_per_hook_pairs", shm->stats.nft_compat_validate_per_hook_pairs);
		stat_row("nftables_churn", "dormant_abort_iters", shm->stats.nft_dormant_abort_iters);
		stat_row("nftables_churn", "dormant_abort_eperm", shm->stats.nft_dormant_abort_eperm);
		stat_row("nftables_churn", "dormant_abort_emsg",  shm->stats.nft_dormant_abort_emsg);
		stat_row("nftables_churn", "dormant_abort_ok",    shm->stats.nft_dormant_abort_ok);
		stat_row("nftables_churn", "xt_ct_iters",         shm->stats.xt_ct_iters);
		stat_row("nftables_churn", "xt_ct_eperm",         shm->stats.xt_ct_eperm);
		stat_row("nftables_churn", "xt_ct_unsupported",   shm->stats.xt_ct_unsupported);
		stat_row("nftables_churn", "xt_ct_set_ok",        shm->stats.xt_ct_set_ok);
		stat_row("nftables_churn", "xt_ct_get_ok",        shm->stats.xt_ct_get_ok);
		stat_row("nftables_churn", "xt_ct_v2_seen",       shm->stats.xt_ct_v2_seen);
		stat_row("nftables_churn", "fwd_loop_runs",             shm->stats.nft_fwd_loop_runs);
		stat_row("nftables_churn", "fwd_loop_ns_setup_failed",  shm->stats.nft_fwd_loop_ns_setup_failed);
		stat_row("nftables_churn", "fwd_loop_probe_sent_ok",    shm->stats.nft_fwd_loop_probe_sent_ok);
		stat_row("nftables_churn", "fwd_loop_completed_ok",     shm->stats.nft_fwd_loop_completed_ok);
		stat_row("nftables_churn", "l4frag_iters",              shm->stats.nft_l4frag_iters);
		stat_row("nftables_churn", "l4frag_install_ok",         shm->stats.nft_l4frag_install_ok);
		stat_row("nftables_churn", "l4frag_rule_ok",            shm->stats.nft_l4frag_rule_ok);
		stat_row("nftables_churn", "l4frag_send_ok",            shm->stats.nft_l4frag_send_ok);
		stat_row("nftables_churn", "l4frag_send_failed",        shm->stats.nft_l4frag_send_failed);
	}

	if (shm->stats.tc_qdisc_churn_runs) {
		stat_row("tc_qdisc_churn", "runs",              shm->stats.tc_qdisc_churn_runs);
		stat_row("tc_qdisc_churn", "setup_failed",      shm->stats.tc_qdisc_churn_setup_failed);
		stat_row("tc_qdisc_churn", "link_create_ok",    shm->stats.tc_qdisc_churn_link_create_ok);
		stat_row("tc_qdisc_churn", "qdisc_create_ok",   shm->stats.tc_qdisc_churn_qdisc_create_ok);
		stat_row("tc_qdisc_churn", "tclass_create_ok",  shm->stats.tc_qdisc_churn_tclass_create_ok);
		stat_row("tc_qdisc_churn", "tfilter_create_ok", shm->stats.tc_qdisc_churn_tfilter_create_ok);
		stat_row("tc_qdisc_churn", "packet_sent_ok",    shm->stats.tc_qdisc_churn_packet_sent_ok);
		stat_row("tc_qdisc_churn", "qdisc_replace_ok",  shm->stats.tc_qdisc_churn_qdisc_replace_ok);
		stat_row("tc_qdisc_churn", "tfilter_del_ok",    shm->stats.tc_qdisc_churn_tfilter_del_ok);
		stat_row("tc_qdisc_churn", "qdisc_del_ok",      shm->stats.tc_qdisc_churn_qdisc_del_ok);
		stat_row("tc_qdisc_churn", "link_del_ok",       shm->stats.tc_qdisc_churn_link_del_ok);
		stat_row("tc_qdisc_churn", "peek_stack_runs",         shm->stats.tc_qdisc_peek_stack_runs);
		stat_row("tc_qdisc_churn", "peek_stack_install_ok",   shm->stats.tc_qdisc_peek_stack_install_ok);
		stat_row("tc_qdisc_churn", "peek_stack_install_fail", shm->stats.tc_qdisc_peek_stack_install_fail);
		stat_row("tc_qdisc_churn", "peek_stack_burst_ok",     shm->stats.tc_qdisc_peek_stack_burst_ok);
		stat_row("tc_qdisc_churn", "bridge_parent_runs",      shm->stats.tc_qdisc_churn_bridge_parent_runs);
		stat_row("tc_qdisc_churn", "bridge_dellink_race_ok",  shm->stats.tc_qdisc_churn_bridge_dellink_race_ok);
	}

	if (shm->stats.tc_mirred_blockcast_runs) {
		stat_row("tc_mirred_blockcast", "runs",            shm->stats.tc_mirred_blockcast_runs);
		stat_row("tc_mirred_blockcast", "setup_failed",    shm->stats.tc_mirred_blockcast_setup_failed);
		stat_row("tc_mirred_blockcast", "qdisc_ok",        shm->stats.tc_mirred_blockcast_qdisc_ok);
		stat_row("tc_mirred_blockcast", "qdisc_fail",      shm->stats.tc_mirred_blockcast_qdisc_fail);
		stat_row("tc_mirred_blockcast", "filter_ok",       shm->stats.tc_mirred_blockcast_filter_ok);
		stat_row("tc_mirred_blockcast", "filter_fail",     shm->stats.tc_mirred_blockcast_filter_fail);
		stat_row("tc_mirred_blockcast", "packet_sent_ok",  shm->stats.tc_mirred_blockcast_packet_sent_ok);
	}

	if (shm->stats.xfrm_churn_runs) {
		stat_row("xfrm_churn", "runs",          shm->stats.xfrm_churn_runs);
		stat_row("xfrm_churn", "setup_failed",  shm->stats.xfrm_churn_setup_failed);
		stat_row("xfrm_churn", "sa_added",      shm->stats.xfrm_churn_sa_added);
		stat_row("xfrm_churn", "sa_updated",    shm->stats.xfrm_churn_sa_updated);
		stat_row("xfrm_churn", "sa_deleted",    shm->stats.xfrm_churn_sa_deleted);
		stat_row("xfrm_churn", "pol_added",     shm->stats.xfrm_churn_pol_added);
		stat_row("xfrm_churn", "pol_deleted",   shm->stats.xfrm_churn_pol_deleted);
		stat_row("xfrm_churn", "esp_sent",      shm->stats.xfrm_churn_esp_sent);
		stat_row("xfrm_churn", "pfkey_send_ok", shm->stats.xfrm_churn_pfkey_send_ok);
		stat_row("xfrm_churn", "ah_esn_setup_ok",    shm->stats.xfrm_ah_esn_setup_ok);
		stat_row("xfrm_churn", "ah_esn_setup_fail",  shm->stats.xfrm_ah_esn_setup_fail);
		stat_row("xfrm_churn", "ah_esn_async_runs",  shm->stats.xfrm_ah_esn_async_runs);
		stat_row("xfrm_churn", "ah_esn_delsa_races", shm->stats.xfrm_ah_esn_delsa_races);
		stat_row("xfrm_churn", "compat_sweep_runs",  shm->stats.xfrm_compat_sweep_runs);
		stat_row("xfrm_churn", "compat_sends_ok",    shm->stats.xfrm_compat_sends_ok);
		stat_row("xfrm_churn", "compat_sends_failed", shm->stats.xfrm_compat_sends_failed);
		stat_row("xfrm_churn", "compat_replies_seen", shm->stats.xfrm_compat_replies_seen);
	}

	stat_category_emit_text(&altname_thrash_category);

	stat_category_emit_text(&ublk_lifecycle_category);

	stat_category_emit_text(&pci_bind_category);

	if (shm->stats.accept_unblocker_connects_fired ||
	    shm->stats.accept_unblocker_loopback_only_skipped ||
	    shm->stats.accept_unblocker_probe_failed) {
		stat_row("accept_unblocker", "connects_fired",
			 shm->stats.accept_unblocker_connects_fired);
		stat_row("accept_unblocker", "loopback_only_skipped",
			 shm->stats.accept_unblocker_loopback_only_skipped);
		stat_row("accept_unblocker", "probe_failed",
			 shm->stats.accept_unblocker_probe_failed);
	}

	if (shm->stats.pipe_waker_bytes_written ||
	    shm->stats.pipe_waker_no_target ||
	    shm->stats.pipe_waker_write_failed) {
		stat_row("pipe_waker", "bytes_written",
			 shm->stats.pipe_waker_bytes_written);
		stat_row("pipe_waker", "no_target",
			 shm->stats.pipe_waker_no_target);
		stat_row("pipe_waker", "write_failed",
			 shm->stats.pipe_waker_write_failed);
	}

	if (shm->stats.nat_t_churn_runs) {
		stat_row("nat_t_churn", "runs",              shm->stats.nat_t_churn_runs);
		stat_row("nat_t_churn", "setup_failed",      shm->stats.nat_t_churn_setup_failed);
		stat_row("nat_t_churn", "sa_added",          shm->stats.nat_t_churn_sa_added);
		stat_row("nat_t_churn", "sa_deleted",        shm->stats.nat_t_churn_sa_deleted);
		stat_row("nat_t_churn", "frames_sent",       shm->stats.nat_t_churn_frames_sent);
		stat_row("nat_t_churn", "xfrm6_setup_ok",    shm->stats.nat_t_xfrm6_setup_ok);
		stat_row("nat_t_churn", "xfrm6_setup_fail",  shm->stats.nat_t_xfrm6_setup_fail);
		stat_row("nat_t_churn", "xfrm6_sendto_runs", shm->stats.nat_t_xfrm6_sendto_runs);
		stat_row("nat_t_churn", "xfrm6_delsa_races", shm->stats.nat_t_xfrm6_delsa_races);
	}

	stat_category_emit_text(&bpf_cgroup_attach_category);

	if (shm->stats.mptcp_pm_churn_runs) {
		stat_row("mptcp_pm_churn", "runs",            shm->stats.mptcp_pm_churn_runs);
		stat_row("mptcp_pm_churn", "setup_failed",    shm->stats.mptcp_pm_churn_setup_failed);
		stat_row("mptcp_pm_churn", "sock_mptcp_ok",   shm->stats.mptcp_pm_churn_sock_mptcp_ok);
		stat_row("mptcp_pm_churn", "addr_added_ok",   shm->stats.mptcp_pm_churn_addr_added_ok);
		stat_row("mptcp_pm_churn", "addr_removed_ok", shm->stats.mptcp_pm_churn_addr_removed_ok);
		stat_row("mptcp_pm_churn", "send_ok",         shm->stats.mptcp_pm_churn_send_ok);
		stat_row("mptcp_pm_churn", "setsockopt_unsupported",   shm->stats.mptcp_setsockopt_unsupported);
		stat_row("mptcp_pm_churn", "setsockopt_master_set",    shm->stats.mptcp_setsockopt_master_set);
		stat_row("mptcp_pm_churn", "setsockopt_master_fail",   shm->stats.mptcp_setsockopt_master_fail);
		stat_row("mptcp_pm_churn", "getsockopt_verify_ok",     shm->stats.mptcp_getsockopt_verify_ok);
		stat_row("mptcp_pm_churn", "getsockopt_verify_drift",  shm->stats.mptcp_getsockopt_verify_drift);
		stat_row("mptcp_pm_churn", "sockopt_sweep_runs",       shm->stats.mptcp_sockopt_sweep_runs);
		stat_row("mptcp_pm_churn", "sockopt_set_ok",           shm->stats.mptcp_sockopt_set_ok);
		stat_row("mptcp_pm_churn", "sockopt_set_failed",       shm->stats.mptcp_sockopt_set_failed);
		stat_row("mptcp_pm_churn", "sockopt_subflow_added",    shm->stats.mptcp_sockopt_subflow_added);
		stat_row("mptcp_pm_churn", "sockopt_readback_ok",      shm->stats.mptcp_sockopt_readback_ok);
		stat_row("mptcp_pm_churn", "sockopt_inherit_mismatch", shm->stats.mptcp_sockopt_inherit_mismatch);
		stat_row("mptcp_pm_churn", "sockopt_unsupported_latched", shm->stats.mptcp_sockopt_unsupported_latched);
	}

	if (shm->stats.devlink_port_churn_iterations ||
	    shm->stats.devlink_port_churn_create_skipped) {
		stat_row("devlink_port_churn", "iterations",     shm->stats.devlink_port_churn_iterations);
		stat_row("devlink_port_churn", "split_ok",       shm->stats.devlink_port_churn_split_ok);
		stat_row("devlink_port_churn", "split_fail",     shm->stats.devlink_port_churn_split_fail);
		stat_row("devlink_port_churn", "reload_ok",      shm->stats.devlink_port_churn_reload_ok);
		stat_row("devlink_port_churn", "reload_fail",    shm->stats.devlink_port_churn_reload_fail);
		stat_row("devlink_port_churn", "create_skipped", shm->stats.devlink_port_churn_create_skipped);
	}

	stat_category_emit_text(&handshake_req_abort_category);

	stat_category_emit_text(&nf_conntrack_helper_churn_category);

	stat_category_emit_text(&af_unix_scm_rights_gc_category);

	stat_category_emit_text(&af_unix_peek_race_category);

	stat_category_emit_text(&sysv_shm_orphan_race_category);

	stat_category_emit_text(&qrtr_bind_race_category);

	stat_category_emit_text(&pfkey_spd_walk_category);

	stat_category_emit_text(&l2tp_ifname_race_category);

	stat_category_emit_text(&netns_teardown_category);

	stat_category_emit_text(&tcp_ulp_swap_churn_category);

	stat_category_emit_text(&msg_zerocopy_churn_category);

	stat_category_emit_text(&setsockopt_pairing_category);

	stat_category_emit_text(&iouring_send_zc_churn_category);

	if (shm->stats.vsock_transport_churn_runs) {
		stat_row("vsock_transport_churn", "runs",           shm->stats.vsock_transport_churn_runs);
		stat_row("vsock_transport_churn", "setup_failed",   shm->stats.vsock_transport_churn_setup_failed);
		stat_row("vsock_transport_churn", "bind_ok",        shm->stats.vsock_transport_churn_bind_ok);
		stat_row("vsock_transport_churn", "connect_ok",     shm->stats.vsock_transport_churn_connect_ok);
		stat_row("vsock_transport_churn", "send_ok",        shm->stats.vsock_transport_churn_send_ok);
		stat_row("vsock_transport_churn", "buffer_size_ok", shm->stats.vsock_transport_churn_buffer_size_ok);
		stat_row("vsock_transport_churn", "timeout_ok",     shm->stats.vsock_transport_churn_timeout_ok);
		stat_row("vsock_transport_churn", "get_cid_ok",     shm->stats.vsock_transport_churn_get_cid_ok);
		stat_row("vsock_transport_churn", "seq_eom_runs",         shm->stats.vsock_seq_eom_runs);
		stat_row("vsock_transport_churn", "seq_eom_sends_ok",     shm->stats.vsock_seq_eom_sends_ok);
		stat_row("vsock_transport_churn", "seq_eom_sends_failed", shm->stats.vsock_seq_eom_sends_failed);
		stat_row("vsock_transport_churn", "seq_eom_skipped",      shm->stats.vsock_seq_eom_skipped);
	}

	stat_category_emit_text(&bridge_vlan_churn_category);

	stat_category_emit_text(&igmp_mld_source_churn_category);

	if (shm->stats.psp_key_rotate_runs) {
		stat_row("psp_key_rotate", "runs",              shm->stats.psp_key_rotate_runs);
		stat_row("psp_key_rotate", "setup_failed",      shm->stats.psp_key_rotate_setup_failed);
		stat_row("psp_key_rotate", "netdev_create_ok",  shm->stats.psp_key_rotate_netdev_create_ok);
		stat_row("psp_key_rotate", "family_resolve_ok", shm->stats.psp_key_rotate_family_resolve_ok);
		stat_row("psp_key_rotate", "dev_get_ok",        shm->stats.psp_key_rotate_dev_get_ok);
		stat_row("psp_key_rotate", "key_install_ok",    shm->stats.psp_key_rotate_key_install_ok);
		stat_row("psp_key_rotate", "spi_set_ok",        shm->stats.psp_key_rotate_spi_set_ok);
		stat_row("psp_key_rotate", "send_ok",           shm->stats.psp_key_rotate_send_ok);
		stat_row("psp_key_rotate", "rotate_ok",         shm->stats.psp_key_rotate_rotate_ok);
		stat_row("psp_key_rotate", "spi_switch_ok",     shm->stats.psp_key_rotate_spi_switch_ok);
		stat_row("psp_key_rotate", "shutdown_ok",       shm->stats.psp_key_rotate_shutdown_ok);
	}

	if (shm->stats.psp_devlink_port_churn_runs) {
		stat_row("psp_devlink_port_churn", "runs",                 shm->stats.psp_devlink_port_churn_runs);
		stat_row("psp_devlink_port_churn", "port_add_ok",          shm->stats.psp_devlink_port_churn_port_add_ok);
		stat_row("psp_devlink_port_churn", "port_del_ok",          shm->stats.psp_devlink_port_churn_port_del_ok);
		stat_row("psp_devlink_port_churn", "vf_spawn_ok",          shm->stats.psp_devlink_port_churn_vf_spawn_ok);
		stat_row("psp_devlink_port_churn", "unsupported_latched",  shm->stats.psp_devlink_port_churn_unsupported_latched);
	}

	stat_category_emit_text(&veth_asymmetric_xdp_category);

	stat_category_emit_text(&ip6erspan_netns_migrate_category);

	stat_category_emit_text(&ip6gre_bond_lapb_stack_category);

	stat_category_emit_text(&wireguard_decrypt_flood_category);

	stat_category_emit_text(&blkdev_lifecycle_race_category);

	stat_category_emit_text(&iscsi_target_probe_category);

	stat_category_emit_text(&iscsi_login_walker_category);

	if (shm->stats.ipvs_sysctl_writer_runs) {
		stat_row("ipvs_sysctl_writer", "runs",                shm->stats.ipvs_sysctl_writer_runs);
		stat_row("ipvs_sysctl_writer", "writes_ok",           shm->stats.ipvs_sysctl_writer_writes_ok);
		stat_row("ipvs_sysctl_writer", "writes_failed",       shm->stats.ipvs_sysctl_writer_writes_failed);
		stat_row("ipvs_sysctl_writer", "unsupported_latched", shm->stats.ipvs_sysctl_writer_unsupported_latched);
	}

	stat_category_emit_text(&ipv6_ndisc_proxy_category);

	if (shm->stats.ipfrag_source_runs) {
		stat_row("ipfrag_source_churn", "runs",            shm->stats.ipfrag_source_runs);
		stat_row("ipfrag_source_churn", "packets_sent_ok", shm->stats.ipfrag_packets_sent_ok);
		stat_row("ipfrag_source_churn", "send_failed",     shm->stats.ipfrag_send_failed);
		stat_row("ipfrag_source_churn", "unique_srcs",     shm->stats.ipfrag_unique_srcs);
	}

	stat_category_emit_text(&rtnl_vf_broadcast_getlink_category);

	if (shm->stats.obscure_af_churn_runs) {
		static const char * const ap_names[] = {
			"sendmsg_no_bind",
			"bind_then_sendmsg",
			"connect_no_listen",
			"ioctl_rotation",
			"setsockopt_zero_len",
			"close_via_dup",
		};
		char key[64];
		unsigned int ap;

		stat_row("obscure_af_churn", "runs",         shm->stats.obscure_af_churn_runs);
		stat_row("obscure_af_churn", "no_viable_pf", shm->stats.obscure_af_churn_no_viable_pf);

		for (ap = 0; ap < ARRAY_SIZE(ap_names); ap++) {
			snprintf(key, sizeof(key), "%s_runs", ap_names[ap]);
			stat_row("obscure_af_churn", key,
				 shm->stats.obscure_af_churn_pattern_runs[ap]);
			snprintf(key, sizeof(key), "%s_kernel_rejected", ap_names[ap]);
			stat_row("obscure_af_churn", key,
				 shm->stats.obscure_af_churn_pattern_kernel_rejected[ap]);
			snprintf(key, sizeof(key), "%s_unexpected_success", ap_names[ap]);
			stat_row("obscure_af_churn", key,
				 shm->stats.obscure_af_churn_pattern_unexpected_success[ap]);
		}
	}

	stat_category_emit_text(&flowtable_encap_vlan_category);

	if (shm->stats.rxrpc_sendmsg_cmsg_runs) {
		static const char * const rxrpc_cmsg_slot_names[8] = {
			"user_call_id",
			"abort",
			"accept",
			"exclusive_call",
			"upgrade_service",
			"tx_length",
			"set_call_timeout",
			"charge_accept",
		};
		char key[64];
		unsigned int slot;

		stat_row("rxrpc_sendmsg_cmsg_churn", "runs",          shm->stats.rxrpc_sendmsg_cmsg_runs);
		stat_row("rxrpc_sendmsg_cmsg_churn", "socket_failed", shm->stats.rxrpc_sendmsg_cmsg_socket_failed);
		stat_row("rxrpc_sendmsg_cmsg_churn", "sendmsg_ok",    shm->stats.rxrpc_sendmsg_cmsg_sendmsg_ok);
		stat_row("rxrpc_sendmsg_cmsg_churn", "sendmsg_fail",  shm->stats.rxrpc_sendmsg_cmsg_sendmsg_fail);
		for (slot = 0; slot < 8U; slot++) {
			snprintf(key, sizeof(key), "cmsg_sent_%s",
				 rxrpc_cmsg_slot_names[slot]);
			stat_row("rxrpc_sendmsg_cmsg_churn", key,
				 shm->stats.rxrpc_sendmsg_cmsg_sent[slot]);
		}
	}

	if (shm->stats.tty_ldisc_churn_runs) {
		char key[64];
		unsigned int slot;

		stat_row("tty_ldisc_churn", "runs",             shm->stats.tty_ldisc_churn_runs);
		stat_row("tty_ldisc_churn", "setup_failed",     shm->stats.tty_ldisc_churn_setup_failed);
		stat_row("tty_ldisc_churn", "ldisc_set_ok",     shm->stats.tty_ldisc_churn_ldisc_set_ok);
		stat_row("tty_ldisc_churn", "ldisc_set_failed", shm->stats.tty_ldisc_churn_ldisc_set_failed);
		stat_row("tty_ldisc_churn", "write_ok",         shm->stats.tty_ldisc_churn_write_ok);
		stat_row("tty_ldisc_churn", "read_ok",          shm->stats.tty_ldisc_churn_read_ok);
		for (slot = 0; slot < 25U; slot++) {
			if (shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[slot] == 0)
				continue;
			snprintf(key, sizeof(key), "ldisc_set_ok_n%u", slot);
			stat_row("tty_ldisc_churn", key,
				 shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[slot]);
		}
	}

	if (shm->stats.afxdp_churn_runs) {
		stat_row("afxdp_churn", "runs",            shm->stats.afxdp_churn_runs);
		stat_row("afxdp_churn", "setup_failed",    shm->stats.afxdp_churn_setup_failed);
		stat_row("afxdp_churn", "umem_reg_ok",     shm->stats.afxdp_churn_umem_reg_ok);
		stat_row("afxdp_churn", "rings_setup_ok",  shm->stats.afxdp_churn_rings_setup_ok);
		stat_row("afxdp_churn", "prog_load_ok",    shm->stats.afxdp_churn_prog_load_ok);
		stat_row("afxdp_churn", "map_create_ok",   shm->stats.afxdp_churn_map_create_ok);
		stat_row("afxdp_churn", "map_update_ok",   shm->stats.afxdp_churn_map_update_ok);
		stat_row("afxdp_churn", "bind_ok",         shm->stats.afxdp_churn_bind_ok);
		stat_row("afxdp_churn", "link_attach_ok",  shm->stats.afxdp_churn_link_attach_ok);
		stat_row("afxdp_churn", "netlink_attach_ok", shm->stats.afxdp_churn_netlink_attach_ok);
		stat_row("afxdp_churn", "attach_failed",   shm->stats.afxdp_churn_attach_failed);
		stat_row("afxdp_churn", "send_ok",         shm->stats.afxdp_churn_send_ok);
		stat_row("afxdp_churn", "recv_ok",         shm->stats.afxdp_churn_recv_ok);
		stat_row("afxdp_churn", "map_delete_ok",   shm->stats.afxdp_churn_map_delete_ok);
		stat_row("afxdp_churn", "munmap_race_ok",  shm->stats.afxdp_churn_munmap_race_ok);
		stat_row("afxdp_churn", "xsg_iters",         shm->stats.afxdp_xsg_iters);
		stat_row("afxdp_churn", "tx_metadata_iters", shm->stats.afxdp_tx_metadata_iters);
		stat_row("afxdp_churn", "tun_bind_iters",    shm->stats.afxdp_tun_bind_iters);
		stat_row("afxdp_churn", "xsg_bind_failed",   shm->stats.afxdp_xsg_bind_failed);
		stat_row("afxdp_churn", "tx_md_bind_failed", shm->stats.afxdp_tx_md_bind_failed);
	}

	if (shm->stats.kvm_run_invocations) {
		stat_row("kvm_run_churn", "invocations",        shm->stats.kvm_run_invocations);
		stat_row("kvm_run_churn", "exit_io",            shm->stats.kvm_run_exit_io);
		stat_row("kvm_run_churn", "exit_mmio",          shm->stats.kvm_run_exit_mmio);
		stat_row("kvm_run_churn", "exit_hlt",           shm->stats.kvm_run_exit_hlt);
		stat_row("kvm_run_churn", "exit_shutdown",      shm->stats.kvm_run_exit_shutdown);
		stat_row("kvm_run_churn", "exit_fail_entry",    shm->stats.kvm_run_exit_fail_entry);
		stat_row("kvm_run_churn", "exit_internal_error", shm->stats.kvm_run_exit_internal_error);
		stat_row("kvm_run_churn", "exit_intr",          shm->stats.kvm_run_exit_intr);
		stat_row("kvm_run_churn", "exit_other",         shm->stats.kvm_run_exit_other);
		stat_row("kvm_run_churn", "errors",             shm->stats.kvm_run_errors);
		stat_row("kvm_run_churn", "gpc_memslot_race_runs",         shm->stats.kvm_gpc_memslot_race_runs);
		stat_row("kvm_run_churn", "gpc_memslot_race_deletes",      shm->stats.kvm_gpc_memslot_race_deletes);
		stat_row("kvm_run_churn", "gpc_memslot_race_unsupported",  shm->stats.kvm_gpc_memslot_race_unsupported);
	}

	if (shm->stats.nl80211_runs) {
		stat_row("nl80211_churn", "runs",                  shm->stats.nl80211_runs);
		stat_row("nl80211_churn", "setup_failed",          shm->stats.nl80211_setup_failed);
		stat_row("nl80211_churn", "scan_triggered",        shm->stats.nl80211_scan_triggered);
		stat_row("nl80211_churn", "connect_attempted",     shm->stats.nl80211_connect_attempted);
		stat_row("nl80211_churn", "connect_succeeded",     shm->stats.nl80211_connect_succeeded);
		stat_row("nl80211_churn", "disconnect_attempted",  shm->stats.nl80211_disconnect_attempted);
		stat_row("nl80211_churn", "regdom_changed",        shm->stats.nl80211_regdom_changed);
		stat_row("nl80211_churn", "iface_created",         shm->stats.nl80211_iface_created);
		stat_row("nl80211_churn", "iface_destroyed",       shm->stats.nl80211_iface_destroyed);
		stat_row("nl80211_churn", "bursts_sent",           shm->stats.nl80211_bursts_sent);
		stat_row("nl80211_churn", "pmsr_runs",             shm->stats.nl80211_pmsr_runs);
		stat_row("nl80211_churn", "pmsr_ok",               shm->stats.nl80211_pmsr_ok);
		stat_row("nl80211_churn", "admin_gate_runs",       shm->stats.nl80211_admin_gate_runs);
		stat_row("nl80211_churn", "admin_gate_eperm_ok",   shm->stats.nl80211_admin_gate_eperm_ok);
		stat_row("nl80211_churn", "admin_gate_unexpected", shm->stats.nl80211_admin_gate_unexpected);
	}

	stat_category_emit_text(&splice_protocols_category);

	stat_category_emit_text(&rxrpc_key_install_category);

	stat_category_emit_text(&af_alg_weak_cipher_probe_category);

	stat_category_emit_text(&sysfs_string_race_category);

	stat_category_emit_text(&fdstress_category);

	if (shm->stats.af_alg_probe_runs || shm->stats.af_alg_probe_unsupported) {
		unsigned int tmpl;

		stat_row("af_alg_probe", "runs",         shm->stats.af_alg_probe_runs);
		stat_row("af_alg_probe", "unsupported",  shm->stats.af_alg_probe_unsupported);
		stat_row("af_alg_probe", "accept_total", shm->stats.af_alg_probe_accept_total);
		stat_row("af_alg_probe", "reject_total", shm->stats.af_alg_probe_reject_total);
		for (tmpl = 0; tmpl < NR_AF_ALG_PROBE_TEMPLATES; tmpl++) {
			char metric[64];
			const char *label = af_alg_probe_template_label(tmpl);

			snprintf(metric, sizeof(metric), "%s.accept", label);
			stat_row("af_alg_probe", metric, shm->stats.af_alg_probe_accept[tmpl]);
			snprintf(metric, sizeof(metric), "%s.reject", label);
			stat_row("af_alg_probe", metric, shm->stats.af_alg_probe_reject[tmpl]);
		}
	}

	if (shm->stats.af_alg_recvmsg_runs) {
		stat_row("af_alg_recvmsg_churn", "runs",               shm->stats.af_alg_recvmsg_runs);
		stat_row("af_alg_recvmsg_churn", "setkey_sent",        shm->stats.af_alg_recvmsg_setkey_sent);
		stat_row("af_alg_recvmsg_churn", "iv_sent",            shm->stats.af_alg_recvmsg_iv_sent);
		stat_row("af_alg_recvmsg_churn", "oob_iov",            shm->stats.af_alg_recvmsg_oob_iov);
		stat_row("af_alg_recvmsg_churn", "zerolen",            shm->stats.af_alg_recvmsg_zerolen);
		stat_row("af_alg_recvmsg_churn", "oversize",           shm->stats.af_alg_recvmsg_oversize);
		stat_row("af_alg_recvmsg_churn", "empty_cmsg_no_more", shm->stats.af_alg_recvmsg_empty_cmsg_no_more);
		stat_row("af_alg_recvmsg_churn", "unsupported",        shm->stats.af_alg_recvmsg_unsupported);
	}
}

/* Helpers shared by the "Top remote-edge producers" view in
 * dump_stats_kcov_block().  The view emits one row per top syscall
 * AND one row per top childop with the same column shape, so both
 * the flag-lookup and the yield-format live here to keep the two
 * render loops free of duplicated logic. */
static void remote_edge_row_flags(char *buf, size_t bufsz,
				  unsigned long row_remote_ecount,
				  unsigned long max_remote_ecount)
{
	/* HEAVY: row carries >= 50% of the leader's remote eCount.
	 * One max is computed across BOTH the syscall and childop
	 * scans before render, so the H mark means the same thing
	 * in either sub-table. */
	bool heavy = (max_remote_ecount > 0) &&
		     (row_remote_ecount * 2 >= max_remote_ecount);

	snprintf(buf, bufsz, "%s", heavy ? "H" : "-");
}

static void remote_edge_format_yield(char *buf, size_t bufsz,
				     unsigned long edge_calls,
				     unsigned long calls)
{
	unsigned long milli;

	if (calls == 0) {
		snprintf(buf, bufsz, "%s", "  --");
		return;
	}
	milli = (edge_calls * 1000UL) / calls;
	if (milli > 1000)
		milli = 1000;
	snprintf(buf, bufsz, "%lu.%03lu", milli / 1000, milli % 1000);
}

void __cold dump_stats_kcov_block(void)
{
	unsigned int i;

	if (kcov_shm != NULL) {
		unsigned int top_nr[10];
		unsigned long top_edges[10];
		unsigned int top_count = 0;
		unsigned int cold_count = 0;
		unsigned int j;

		unsigned long kc_edges       = __atomic_load_n(&kcov_shm->edges_found,            __ATOMIC_RELAXED);
		/* See per-child kcov stats migration in stats_ring.h:
		 * total_pcs / total_calls / remote_calls read from
		 * parent_stats.  kcov_shm->total_calls is kept as the
		 * stamp source for last_edge_at[] / last_efault_at[];
		 * the other two shm fields are no longer bumped. */
		unsigned long kc_pcs         = parent_stats.total_pcs;
		unsigned long kc_calls       = parent_stats.total_calls;
		unsigned long kc_remote      = parent_stats.remote_calls;
		unsigned long kc_cmp_records = __atomic_load_n(&kcov_shm->cmp_records_collected,  __ATOMIC_RELAXED);
		unsigned long kc_cmp_trunc   = __atomic_load_n(&kcov_shm->cmp_trace_truncated,    __ATOMIC_RELAXED);
		unsigned long kc_dedup_overflow    = __atomic_load_n(&kcov_shm->dedup_probe_overflow,   __ATOMIC_RELAXED);
		unsigned long kc_dedup_max_probe   = __atomic_load_n(&kcov_shm->dedup_max_probe_seen,   __ATOMIC_RELAXED);
		unsigned long kc_cmp_bloom_skipped = __atomic_load_n(&kcov_shm->cmp_hints_bloom_skipped, __ATOMIC_RELAXED);
		unsigned long kc_cmp_strip_skipped = __atomic_load_n(&kcov_shm->cmp_hints_strip_skipped, __ATOMIC_RELAXED);
		unsigned long kc_cmp_unique  = __atomic_load_n(&kcov_shm->cmp_hints_unique_inserts, __ATOMIC_RELAXED);
		unsigned long kc_cmp_save_reject_nonconst      = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_nonconst,      __ATOMIC_RELAXED);
		unsigned long kc_cmp_save_reject_uninteresting = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_uninteresting, __ATOMIC_RELAXED);
		unsigned long kc_cmp_save_reject_sentinel      = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_sentinel,      __ATOMIC_RELAXED);
		unsigned long kc_cmp_save_reject_dup           = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_dup,           __ATOMIC_RELAXED);
		unsigned long kc_cmp_save_reject_cap           = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_cap,           __ATOMIC_RELAXED);

		stat_row("kcov_coverage", "unique_edges",          kc_edges);
		stat_row("kcov_coverage", "total_pcs",             kc_pcs);
		stat_row("kcov_coverage", "total_calls",           kc_calls);
		stat_row("kcov_coverage", "remote_calls",          kc_remote);
		stat_row("kcov_coverage", "cmp_records_collected", kc_cmp_records);

		/* Shadow transition-coverage globals.  See the
		 * kcov_transition_coverage_mode enum + KCOV_NUM_TRANSITIONS
		 * comments in include/kcov.h for the design; this block
		 * surfaces the two run-wide counters so PC vs transition
		 * yield can be compared side-by-side without parsing a
		 * separate log channel.  Both stay at zero when the mode is
		 * OFF, so the early-out below keeps the stats stream quiet
		 * for runs that opted out. */
		{
			unsigned long kc_tedges = __atomic_load_n(
				&kcov_shm->transition_edges_found,
				__ATOMIC_RELAXED);
			unsigned long kc_tdistinct = __atomic_load_n(
				&kcov_shm->transition_distinct_edges,
				__ATOMIC_RELAXED);

			if (kc_tedges > 0)
				stat_row("kcov_coverage",
					 "transition_edges_found",
					 kc_tedges);
			if (kc_tdistinct > 0)
				stat_row("kcov_coverage",
					 "transition_distinct_edges",
					 kc_tdistinct);
		}
		if (kc_cmp_trunc > 0)
			stat_row("kcov_coverage", "cmp_trace_truncated", kc_cmp_trunc);
		if (kc_dedup_overflow > 0)
			stat_row("kcov_coverage", "dedup_probe_overflow", kc_dedup_overflow);
		if (kc_dedup_max_probe > 0)
			stat_row("kcov_coverage", "dedup_max_probe_seen", kc_dedup_max_probe);
		if (kc_cmp_bloom_skipped > 0)
			stat_row("kcov_coverage", "cmp_hints_bloom_skipped", kc_cmp_bloom_skipped);
		if (kc_cmp_strip_skipped > 0)
			stat_row("kcov_coverage", "cmp_hints_strip_skipped", kc_cmp_strip_skipped);
		if (kc_cmp_unique > 0)
			stat_row("kcov_coverage", "cmp_hints_unique_inserts", kc_cmp_unique);
		if (kc_cmp_save_reject_nonconst > 0)
			stat_row("kcov_coverage", "cmp_hints_save_reject_nonconst", kc_cmp_save_reject_nonconst);
		if (kc_cmp_save_reject_uninteresting > 0)
			stat_row("kcov_coverage", "cmp_hints_save_reject_uninteresting", kc_cmp_save_reject_uninteresting);
		if (kc_cmp_save_reject_sentinel > 0)
			stat_row("kcov_coverage", "cmp_hints_save_reject_sentinel", kc_cmp_save_reject_sentinel);
		if (kc_cmp_save_reject_dup > 0)
			stat_row("kcov_coverage", "cmp_hints_save_reject_dup", kc_cmp_save_reject_dup);
		if (kc_cmp_save_reject_cap > 0)
			stat_row("kcov_coverage", "cmp_hints_save_reject_cap", kc_cmp_save_reject_cap);

		/* CMP-hint freshness / tier observability rollup.  See the
		 * counter-block comment in include/kcov.h next to
		 * cmp_hint_tier_recent_wins for the per-counter semantics.
		 * Gates on a non-zero summed value so a run that never
		 * exercised the consumer path stays silent in stats.  Per-
		 * bucket detail rendered as a compact tier_age_<n> row
		 * family so a downstream stats consumer can index by
		 * bucket without parsing a sub-structured value. */
		{
			unsigned long kc_tier_r_wins = __atomic_load_n(
				&kcov_shm->cmp_hint_tier_recent_wins,
				__ATOMIC_RELAXED);
			unsigned long kc_tier_r_misses = __atomic_load_n(
				&kcov_shm->cmp_hint_tier_recent_misses,
				__ATOMIC_RELAXED);
			unsigned long kc_tier_d_wins = __atomic_load_n(
				&kcov_shm->cmp_hint_tier_durable_wins,
				__ATOMIC_RELAXED);
			unsigned long kc_tier_d_misses = __atomic_load_n(
				&kcov_shm->cmp_hint_tier_durable_misses,
				__ATOMIC_RELAXED);
			unsigned long sum = kc_tier_r_wins + kc_tier_r_misses
					  + kc_tier_d_wins + kc_tier_d_misses;
			unsigned int b;

			if (sum > 0) {
				stat_row("kcov_coverage",
					 "cmp_hint_tier_recent_wins",
					 kc_tier_r_wins);
				stat_row("kcov_coverage",
					 "cmp_hint_tier_recent_misses",
					 kc_tier_r_misses);
				stat_row("kcov_coverage",
					 "cmp_hint_tier_durable_wins",
					 kc_tier_d_wins);
				stat_row("kcov_coverage",
					 "cmp_hint_tier_durable_misses",
					 kc_tier_d_misses);

				for (b = 0; b < CMP_HINT_AGE_BUCKETS; b++) {
					char key[64];
					unsigned long v_consumed =
						__atomic_load_n(&kcov_shm->cmp_hint_durable_consumed_age[b],
								__ATOMIC_RELAXED);
					unsigned long v_wins =
						__atomic_load_n(&kcov_shm->cmp_hint_durable_age_wins[b],
								__ATOMIC_RELAXED);
					unsigned long v_misses =
						__atomic_load_n(&kcov_shm->cmp_hint_durable_age_misses[b],
								__ATOMIC_RELAXED);

					if ((v_consumed | v_wins | v_misses) == 0)
						continue;
					snprintf(key, sizeof(key),
						 "cmp_hint_durable_consumed_age_%u", b);
					stat_row("kcov_coverage", key, v_consumed);
					snprintf(key, sizeof(key),
						 "cmp_hint_durable_age_wins_%u", b);
					stat_row("kcov_coverage", key, v_wins);
					snprintf(key, sizeof(key),
						 "cmp_hint_durable_age_misses_%u", b);
					stat_row("kcov_coverage", key, v_misses);
				}
			}
		}

		{
			/* total_warm_known_hits migrated off the kcov_shm
			 * atomic onto the per-child staged counter drained
			 * into parent_stats; the shm field is write-dead but
			 * kept for shared-mapping ABI stability.  See
			 * stats_ring.h. */
			unsigned long warm_known = parent_stats.total_warm_known_hits;
			if (warm_known > 0)
				stat_row("kcov_coverage", "warm_known_hits", warm_known);
		}

		{
			unsigned long rx_attempts = __atomic_load_n(&kcov_shm->reexec_attempts, __ATOMIC_RELAXED);
			unsigned long rx_attribution_found = __atomic_load_n(&kcov_shm->reexec_attribution_found, __ATOMIC_RELAXED);
			unsigned long rx_attribution_ambiguous = __atomic_load_n(&kcov_shm->reexec_attribution_ambiguous, __ATOMIC_RELAXED);
			unsigned long rx_attribution_width_match = __atomic_load_n(&kcov_shm->reexec_attribution_width_match, __ATOMIC_RELAXED);
			unsigned long rx_new_cmps_total = __atomic_load_n(&kcov_shm->reexec_new_cmps_total, __ATOMIC_RELAXED);
			unsigned long rx_skipped_destructive = __atomic_load_n(&kcov_shm->reexec_skipped_destructive, __ATOMIC_RELAXED);
			unsigned long rx_skipped_validate_silent = __atomic_load_n(&kcov_shm->reexec_skipped_validate_silent, __ATOMIC_RELAXED);
			unsigned long rx_window_cap_hit = __atomic_load_n(&kcov_shm->reexec_window_cap_hit, __ATOMIC_RELAXED);
			unsigned long rx_parent_calls_enabled = __atomic_load_n(&kcov_shm->cmp_parent_calls_enabled, __ATOMIC_RELAXED);
			unsigned long rx_parent_calls_control = __atomic_load_n(&kcov_shm->cmp_parent_calls_control, __ATOMIC_RELAXED);
			unsigned long rx_parent_new_cmps_enabled = __atomic_load_n(&kcov_shm->cmp_parent_new_cmps_enabled, __ATOMIC_RELAXED);
			unsigned long rx_parent_new_cmps_control = __atomic_load_n(&kcov_shm->cmp_parent_new_cmps_control, __ATOMIC_RELAXED);
			unsigned long rx_gate_skip_in_reexec = __atomic_load_n(&kcov_shm->reexec_gate_skip_in_reexec, __ATOMIC_RELAXED);
			unsigned long rx_gate_skip_disabled = __atomic_load_n(&kcov_shm->reexec_gate_skip_disabled, __ATOMIC_RELAXED);
			unsigned long rx_gate_skip_mode = __atomic_load_n(&kcov_shm->reexec_gate_skip_mode, __ATOMIC_RELAXED);
			unsigned long rx_gate_skip_chain_mid = __atomic_load_n(&kcov_shm->reexec_gate_skip_chain_mid, __ATOMIC_RELAXED);
			unsigned long rx_gate_skip_no_new_cmp = __atomic_load_n(&kcov_shm->reexec_gate_skip_no_new_cmp, __ATOMIC_RELAXED);
			unsigned long rx_gate_skip_no_pending = __atomic_load_n(&kcov_shm->reexec_gate_skip_no_pending, __ATOMIC_RELAXED);
			unsigned long rx_gate_skip_rate = __atomic_load_n(&kcov_shm->reexec_gate_skip_rate, __ATOMIC_RELAXED);
			unsigned long rx_gate_pass = __atomic_load_n(&kcov_shm->reexec_gate_pass, __ATOMIC_RELAXED);

			if (rx_attempts > 0)
				stat_row("kcov_coverage", "reexec_attempts", rx_attempts);
			if (rx_attribution_found > 0)
				stat_row("kcov_coverage", "reexec_attribution_found", rx_attribution_found);
			if (rx_attribution_ambiguous > 0)
				stat_row("kcov_coverage", "reexec_attribution_ambiguous", rx_attribution_ambiguous);
			if (rx_attribution_width_match > 0)
				stat_row("kcov_coverage", "reexec_attribution_width_match", rx_attribution_width_match);
			if (rx_new_cmps_total > 0)
				stat_row("kcov_coverage", "reexec_new_cmps_total", rx_new_cmps_total);
			if (rx_skipped_destructive > 0)
				stat_row("kcov_coverage", "reexec_skipped_destructive", rx_skipped_destructive);
			if (rx_skipped_validate_silent > 0)
				stat_row("kcov_coverage", "reexec_skipped_validate_silent", rx_skipped_validate_silent);
			if (rx_window_cap_hit > 0)
				stat_row("kcov_coverage", "reexec_window_cap_hit", rx_window_cap_hit);
			if (rx_parent_calls_enabled > 0)
				stat_row("kcov_coverage", "cmp_parent_calls_enabled", rx_parent_calls_enabled);
			if (rx_parent_calls_control > 0)
				stat_row("kcov_coverage", "cmp_parent_calls_control", rx_parent_calls_control);
			if (rx_parent_new_cmps_enabled > 0)
				stat_row("kcov_coverage", "cmp_parent_new_cmps_enabled", rx_parent_new_cmps_enabled);
			if (rx_parent_new_cmps_control > 0)
				stat_row("kcov_coverage", "cmp_parent_new_cmps_control", rx_parent_new_cmps_control);
			if (rx_gate_skip_in_reexec > 0)
				stat_row("kcov_coverage", "reexec_gate_skip_in_reexec", rx_gate_skip_in_reexec);
			if (rx_gate_skip_disabled > 0)
				stat_row("kcov_coverage", "reexec_gate_skip_disabled", rx_gate_skip_disabled);
			if (rx_gate_skip_mode > 0)
				stat_row("kcov_coverage", "reexec_gate_skip_mode", rx_gate_skip_mode);
			if (rx_gate_skip_chain_mid > 0)
				stat_row("kcov_coverage", "reexec_gate_skip_chain_mid", rx_gate_skip_chain_mid);
			if (rx_gate_skip_no_new_cmp > 0)
				stat_row("kcov_coverage", "reexec_gate_skip_no_new_cmp", rx_gate_skip_no_new_cmp);
			if (rx_gate_skip_no_pending > 0)
				stat_row("kcov_coverage", "reexec_gate_skip_no_pending", rx_gate_skip_no_pending);
			if (rx_gate_skip_rate > 0)
				stat_row("kcov_coverage", "reexec_gate_skip_rate", rx_gate_skip_rate);
			if (rx_gate_pass > 0)
				stat_row("kcov_coverage", "reexec_gate_pass", rx_gate_pass);
		}

		{
			unsigned long fx_scanned = __atomic_load_n(&kcov_shm->cmp_field_attribution_scanned, __ATOMIC_RELAXED);
			unsigned long fx_found = __atomic_load_n(&kcov_shm->cmp_field_attribution_found, __ATOMIC_RELAXED);
			unsigned long fx_pool_full = __atomic_load_n(&kcov_shm->cmp_field_attribution_pool_full, __ATOMIC_RELAXED);
			unsigned long fx_bad_ptr = __atomic_load_n(&kcov_shm->cmp_field_attribution_arg_skipped_bad_ptr, __ATOMIC_RELAXED);
			unsigned long fx_short_alloc = __atomic_load_n(&kcov_shm->cmp_field_attribution_arg_skipped_short_alloc, __ATOMIC_RELAXED);
			unsigned long fx_ts_bad_ptr = __atomic_load_n(&kcov_shm->cmp_field_timespec_skipped_bad_ptr, __ATOMIC_RELAXED);

			if (fx_scanned > 0)
				stat_row("kcov_coverage", "cmp_field_attribution_scanned", fx_scanned);
			if (fx_found > 0)
				stat_row("kcov_coverage", "cmp_field_attribution_found", fx_found);
			if (fx_pool_full > 0)
				stat_row("kcov_coverage", "cmp_field_attribution_pool_full", fx_pool_full);
			if (fx_bad_ptr > 0)
				stat_row("kcov_coverage", "cmp_field_attribution_arg_skipped_bad_ptr", fx_bad_ptr);
			if (fx_short_alloc > 0)
				stat_row("kcov_coverage", "cmp_field_attribution_arg_skipped_short_alloc", fx_short_alloc);
			if (fx_ts_bad_ptr > 0)
				stat_row("kcov_coverage", "cmp_field_timespec_skipped_bad_ptr", fx_ts_bad_ptr);
		}

		{
			unsigned long rc_inserts = __atomic_load_n(&kcov_shm->cmp_recent_inserts, __ATOMIC_RELAXED);
			unsigned long rc_evicts = __atomic_load_n(&kcov_shm->cmp_recent_evicts, __ATOMIC_RELAXED);
			unsigned long rc_would_pick = __atomic_load_n(&kcov_shm->cmp_recent_would_pick, __ATOMIC_RELAXED);
			unsigned long rc_would_miss = __atomic_load_n(&kcov_shm->cmp_recent_would_miss, __ATOMIC_RELAXED);
			unsigned long rc_live_picks = __atomic_load_n(&kcov_shm->cmp_recent_live_picks, __ATOMIC_RELAXED);

			if (rc_inserts > 0)
				stat_row("kcov_coverage", "cmp_recent_inserts", rc_inserts);
			if (rc_evicts > 0)
				stat_row("kcov_coverage", "cmp_recent_evicts", rc_evicts);
			if (rc_would_pick > 0)
				stat_row("kcov_coverage", "cmp_recent_would_pick", rc_would_pick);
			if (rc_would_miss > 0)
				stat_row("kcov_coverage", "cmp_recent_would_miss", rc_would_miss);
			if (rc_live_picks > 0)
				stat_row("kcov_coverage", "cmp_recent_live_picks", rc_live_picks);
		}

		{
			unsigned long plateau_entered_v = __atomic_load_n(&shm->stats.plateau_entered, __ATOMIC_RELAXED);
			unsigned long plateau_exited_v = __atomic_load_n(&shm->stats.plateau_exited, __ATOMIC_RELAXED);
			unsigned long bucket_canary_checks_v = __atomic_load_n(&shm->stats.bucket_canary_checks, __ATOMIC_RELAXED);
			unsigned long bucket_canary_deficits_v = __atomic_load_n(&shm->stats.bucket_canary_deficits, __ATOMIC_RELAXED);

			if (plateau_entered_v > 0)
				stat_row("kcov_coverage", "plateau_entered", plateau_entered_v);
			if (plateau_exited_v > 0)
				stat_row("kcov_coverage", "plateau_exited", plateau_exited_v);
			if (bucket_canary_checks_v > 0)
				stat_row("kcov_coverage", "bucket_canary_checks", bucket_canary_checks_v);
			if (bucket_canary_deficits_v > 0)
				stat_row("kcov_coverage", "bucket_canary_deficits", bucket_canary_deficits_v);
		}

		/* Find top 10 edge-producing syscalls via insertion sort. */
		unsigned int nr_syscalls_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
		if (nr_syscalls_to_scan > MAX_NR_SYSCALL)
			nr_syscalls_to_scan = MAX_NR_SYSCALL;
		const struct syscalltable *table = biarch ? syscalls_64bit : syscalls;

		memset(top_edges, 0, sizeof(top_edges));
		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long edges = __atomic_load_n(&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);

			if (edges == 0)
				continue;

			if (kcov_syscall_is_cold(i))
				cold_count++;

			topn_push(top_edges, top_nr, &top_count, 10, edges, i);
		}

		if (top_count > 0) {
			output(0, "Top edge-producing syscalls:\n");
			for (j = 0; j < top_count; j++) {
				struct syscallentry *entry = table[top_nr[j]].entry;
				const char *name = entry ? entry->name : "???";

				output(0, "  %-24s %lu\n", name, top_edges[j]);
			}
		}

		/* Top-N by per-interval edge growth (delta since last dump_stats). */
		{
			unsigned int delta_nr[10];
			unsigned long delta_edges[10];
			unsigned int delta_count = 0;
			bool any_delta = false;

			memset(delta_edges, 0, sizeof(delta_edges));
			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long prev = kcov_shm->per_syscall_edges_previous[i];
				unsigned long curr = __atomic_load_n(&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);
				unsigned long delta = (curr > prev) ? curr - prev : 0;

				if (delta > 0)
					any_delta = true;

				if (delta == 0)
					continue;

				topn_push(delta_edges, delta_nr, &delta_count, 10, delta, i);
			}

			if (any_delta && delta_count > 0) {
				output(0, "Top syscalls by recent edge growth:\n");
				for (j = 0; j < delta_count; j++) {
					struct syscallentry *entry = table[delta_nr[j]].entry;
					const char *name = entry ? entry->name : "???";

					output(0, "  %-24s +%lu\n", name, delta_edges[j]);
				}
			}

			/* Snapshot current counts for the next interval. */
			for (i = 0; i < nr_syscalls_to_scan; i++)
				kcov_shm->per_syscall_edges_previous[i] =
					__atomic_load_n(&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);
		}

		/* Shadow transition coverage: top-N by real transition-slot
		 * count (cumulative since process start, not since the last
		 * dump) and top-N by per-interval call-count delta.  Printed
		 * directly beside the PC top-N blocks above so the two
		 * signals can be compared at a glance — a syscall that
		 * appears in the transition top-N but not in the PC top-N is
		 * a candidate for the "new control-flow path through warm
		 * code" pattern that the PC bitmap misses by design.  Both
		 * blocks are silent when transition coverage is OFF: the per-
		 * syscall arrays stay zero, so the any_* gates skip the
		 * headers. */
		{
			unsigned int tr_top_nr[10];
			unsigned long tr_top_edges[10];
			unsigned int tr_top_count = 0;
			bool any_tr = false;

			memset(tr_top_edges, 0, sizeof(tr_top_edges));
			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long tedges = __atomic_load_n(
					&kcov_shm->per_syscall_transition_edges_real[i],
					__ATOMIC_RELAXED);

				if (tedges == 0)
					continue;
				any_tr = true;
				topn_push(tr_top_edges, tr_top_nr, &tr_top_count,
					  10, tedges, i);
			}

			if (any_tr && tr_top_count > 0) {
				output(0, "Top transition-producing syscalls (shadow):\n");
				for (j = 0; j < tr_top_count; j++) {
					struct syscallentry *entry = table[tr_top_nr[j]].entry;
					const char *name = entry ? entry->name : "???";

					output(0, "  %-24s %lu\n",
					       name, tr_top_edges[j]);
				}
			}
		}

		{
			unsigned int tr_delta_nr[10];
			unsigned long tr_delta_edges[10];
			unsigned int tr_delta_count = 0;
			bool any_tr_delta = false;

			memset(tr_delta_edges, 0, sizeof(tr_delta_edges));
			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long prev = kcov_shm->per_syscall_transition_edges_previous[i];
				unsigned long curr = __atomic_load_n(
					&kcov_shm->per_syscall_transition_edges[i],
					__ATOMIC_RELAXED);
				unsigned long delta = (curr > prev) ? curr - prev : 0;

				if (delta > 0)
					any_tr_delta = true;
				if (delta == 0)
					continue;

				topn_push(tr_delta_edges, tr_delta_nr,
					  &tr_delta_count, 10, delta, i);
			}

			if (any_tr_delta && tr_delta_count > 0) {
				output(0, "Top syscalls by recent transition growth (shadow):\n");
				for (j = 0; j < tr_delta_count; j++) {
					struct syscallentry *entry = table[tr_delta_nr[j]].entry;
					const char *name = entry ? entry->name : "???";

					output(0, "  %-24s +%lu\n",
					       name, tr_delta_edges[j]);
				}
			}

			for (i = 0; i < nr_syscalls_to_scan; i++)
				kcov_shm->per_syscall_transition_edges_previous[i] =
					__atomic_load_n(
						&kcov_shm->per_syscall_transition_edges[i],
						__ATOMIC_RELAXED);
		}

		/* Sibling of "Top syscalls by recent edge growth": top-N by
		 * delta of per_syscall_cmp_inserts since the last dump_stats().
		 * A syscall whose CMP-insert rate is high while its edge-growth
		 * rate is flat is producing CMP signal that is not turning into
		 * coverage -- the CMP-rising-PC-flat plateau pattern. */
		{
			unsigned int cmp_delta_nr[10];
			unsigned long cmp_delta_inserts[10];
			unsigned int cmp_delta_count = 0;
			bool any_cmp_delta = false;

			memset(cmp_delta_inserts, 0, sizeof(cmp_delta_inserts));
			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long prev = kcov_shm->per_syscall_cmp_inserts_previous[i];
				unsigned long curr = __atomic_load_n(&kcov_shm->per_syscall_cmp_inserts[i], __ATOMIC_RELAXED);
				unsigned long delta = (curr > prev) ? curr - prev : 0;

				if (delta > 0)
					any_cmp_delta = true;

				if (delta == 0)
					continue;

				topn_push(cmp_delta_inserts, cmp_delta_nr, &cmp_delta_count, 10, delta, i);
			}

			if (any_cmp_delta && cmp_delta_count > 0) {
				output(0, "Top syscalls by CMP unique inserts (since last dump):\n");
				for (j = 0; j < cmp_delta_count; j++) {
					struct syscallentry *entry = table[cmp_delta_nr[j]].entry;
					const char *name = entry ? entry->name : "???";

					output(0, "  %-24s +%lu\n", name, cmp_delta_inserts[j]);
				}
			}

			for (i = 0; i < nr_syscalls_to_scan; i++)
				kcov_shm->per_syscall_cmp_inserts_previous[i] =
					__atomic_load_n(&kcov_shm->per_syscall_cmp_inserts[i], __ATOMIC_RELAXED);
		}

		if (cold_count > 0) {
			output(0, "Cold syscalls (need better sanitise): %u\n", cold_count);
			for (i = 0; i < nr_syscalls_to_scan; i++) {
				struct syscallentry *entry;

				unsigned long slot_edges = __atomic_load_n(&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);

				if (slot_edges == 0)
					continue;
				if (!kcov_syscall_is_cold(i))
					continue;

				entry = table[i].entry;
				output(0, "  %-24s (edges:%lu, last new @ call %lu)\n",
					entry ? entry->name : "???",
					slot_edges,
					kcov_shm->last_edge_at[i]);
			}
		}

		/* Per-syscall errno histogram.  Sibling to the top edge-
		 * producing / cold-syscalls tables above: same MAX_NR_SYSCALL-
		 * indexed walk, same all-zero-row skip, same column-width
		 * convention as the "Top edge-producing syscalls" block.  Eight
		 * buckets in dump order: success, EFAULT, EINVAL, ENOSYS,
		 * EPERM, EBADF, EAGAIN, other.  Bumped from handle_syscall_ret()
		 * next to where the existing entry->failures / entry->errnos[]
		 * tallies are updated.  Sort order matches the top-edges block:
		 * descending by total syscall activity (sum of all eight
		 * buckets) so the syscalls doing the most work appear first. */
		{
			unsigned int errno_top_nr[10];
			unsigned long errno_top_total[10];
			unsigned long errno_top_buckets[10][ERRNO_BUCKET_NR];
			unsigned int errno_top_count = 0;

			memset(errno_top_total, 0, sizeof(errno_top_total));
			memset(errno_top_buckets, 0, sizeof(errno_top_buckets));

			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long buckets[ERRNO_BUCKET_NR];
				unsigned long total = 0;
				unsigned int b;

				for (b = 0; b < ERRNO_BUCKET_NR; b++) {
					buckets[b] = __atomic_load_n(&kcov_shm->per_syscall_errno[i][b],
								     __ATOMIC_RELAXED);
					total += buckets[b];
				}

				/* Skip rows where all eight buckets are zero --
				 * mirrors the top-edges block's `edges == 0`
				 * skip.  A syscall that was never attempted (or
				 * was attempted but never reached AFTER) contributes
				 * nothing and would just be table noise. */
				if (total == 0)
					continue;

				/* Insertion sort, same shape as the top-edges block. */
				for (j = errno_top_count;
				     j > 0 && total > errno_top_total[j - 1]; j--) {
					if (j < 10) {
						errno_top_total[j] = errno_top_total[j - 1];
						errno_top_nr[j] = errno_top_nr[j - 1];
						memcpy(errno_top_buckets[j],
						       errno_top_buckets[j - 1],
						       sizeof(errno_top_buckets[j]));
					}
				}
				if (j < 10) {
					errno_top_total[j] = total;
					errno_top_nr[j] = i;
					memcpy(errno_top_buckets[j], buckets,
					       sizeof(errno_top_buckets[j]));
					if (errno_top_count < 10)
						errno_top_count++;
				}
			}

			if (errno_top_count > 0) {
				output(0, "Top syscalls by errno-histogram activity:\n");
				output(0, "  %-24s %10s %8s %8s %8s %8s %8s %8s %8s\n",
				       "syscall", "ok", "EFAULT", "EINVAL",
				       "ENOSYS", "EPERM", "EBADF", "EAGAIN", "other");
				for (j = 0; j < errno_top_count; j++) {
					struct syscallentry *entry = table[errno_top_nr[j]].entry;
					const char *name = entry ? entry->name : "???";

					output(0, "  %-24s %10lu %8lu %8lu %8lu %8lu %8lu %8lu %8lu\n",
					       name,
					       errno_top_buckets[j][ERRNO_BUCKET_SUCCESS],
					       errno_top_buckets[j][ERRNO_BUCKET_EFAULT],
					       errno_top_buckets[j][ERRNO_BUCKET_EINVAL],
					       errno_top_buckets[j][ERRNO_BUCKET_ENOSYS],
					       errno_top_buckets[j][ERRNO_BUCKET_EPERM],
					       errno_top_buckets[j][ERRNO_BUCKET_EBADF],
					       errno_top_buckets[j][ERRNO_BUCKET_EAGAIN],
					       errno_top_buckets[j][ERRNO_BUCKET_OTHER]);
				}
			}
		}

		/* Credential-class oracle dump.  Always-on observability:
		 * per-class call / success / EPERM / EINVAL / throttled
		 * counts so the operator can spot a class burning attempts
		 * with zero successes (the diagnostic signature the throttle
		 * exists to fix) without grepping the per-syscall errno
		 * histogram for the nine credential names by hand.  The
		 * `throttled` column is bumped only when --cred-throttle is
		 * on and the gate fired; non-zero values double as a "flag
		 * was active and engaged" indicator.  Silent when no class
		 * has any activity. */
		{
			bool any = false;
			unsigned int c;

			for (c = 0; c < CRED_CLASS_NR; c++) {
				if (__atomic_load_n(&shm->stats.cred_class_calls[c],
						    __ATOMIC_RELAXED) != 0) {
					any = true;
					break;
				}
			}
			if (any) {
				output(0, "Credential-class oracle (--cred-throttle %s):\n",
				       cred_throttle ? "ON" : "OFF");
				output(0, "  %-12s %10s %10s %10s %10s %10s\n",
				       "class", "calls", "success",
				       "EPERM", "EINVAL", "throttled");
				for (c = 0; c < CRED_CLASS_NR; c++) {
					unsigned long calls = __atomic_load_n(
						&shm->stats.cred_class_calls[c],
						__ATOMIC_RELAXED);
					unsigned long succ = __atomic_load_n(
						&shm->stats.cred_class_success[c],
						__ATOMIC_RELAXED);
					unsigned long eperm = __atomic_load_n(
						&shm->stats.cred_class_eperm[c],
						__ATOMIC_RELAXED);
					unsigned long einval = __atomic_load_n(
						&shm->stats.cred_class_einval[c],
						__ATOMIC_RELAXED);
					unsigned long thr = __atomic_load_n(
						&shm->stats.cred_class_throttled[c],
						__ATOMIC_RELAXED);

					if (calls == 0 && thr == 0)
						continue;
					output(0, "  %-12s %10lu %10lu %10lu %10lu %10lu\n",
					       cred_class_name[c], calls,
					       succ, eperm, einval, thr);
				}
			}
		}

		/* per-syscall +
		 * per-childop local-vs-remote PC yield, top-N by combined
		 * call count.  Lets the operator see whether a static
		 * remote-sampling policy is spending samples on a mode that
		 * yields no fresh edges -- the global remote_calls counter
		 * above can't answer that question.  Silent when no slot has
		 * any combined activity; columns: calls / edge-calls /
		 * raw-edge-count per mode. */
		{
			unsigned int lr_top_nr[10];
			unsigned long lr_top_total[10];
			unsigned int lr_top_count = 0;

			memset(lr_top_total, 0, sizeof(lr_top_total));
			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long lc = __atomic_load_n(
					&kcov_shm->local_pc_calls[i],
					__ATOMIC_RELAXED);
				unsigned long rc = __atomic_load_n(
					&kcov_shm->remote_pc_calls[i],
					__ATOMIC_RELAXED);
				unsigned long tot = lc + rc;

				if (tot == 0)
					continue;
				topn_push(lr_top_total, lr_top_nr,
					  &lr_top_count, 10, tot, i);
			}
			if (lr_top_count > 0) {
				output(0, "Local vs remote PC yield per syscall (top by combined calls):\n");
				output(0, "  %-24s %10s %10s %10s %10s %10s %10s\n",
				       "syscall",
				       "loc_calls", "loc_eCalls", "loc_eCount",
				       "rem_calls", "rem_eCalls", "rem_eCount");
				for (j = 0; j < lr_top_count; j++) {
					struct syscallentry *entry =
						table[lr_top_nr[j]].entry;
					const char *name = entry ? entry->name : "???";
					unsigned int nr = lr_top_nr[j];
					unsigned long lc = __atomic_load_n(
						&kcov_shm->local_pc_calls[nr],
						__ATOMIC_RELAXED);
					unsigned long lec = __atomic_load_n(
						&kcov_shm->local_pc_edge_calls[nr],
						__ATOMIC_RELAXED);
					unsigned long len_ = __atomic_load_n(
						&kcov_shm->local_pc_edge_count[nr],
						__ATOMIC_RELAXED);
					unsigned long rc = __atomic_load_n(
						&kcov_shm->remote_pc_calls[nr],
						__ATOMIC_RELAXED);
					unsigned long rec = __atomic_load_n(
						&kcov_shm->remote_pc_edge_calls[nr],
						__ATOMIC_RELAXED);
					unsigned long ren = __atomic_load_n(
						&kcov_shm->remote_pc_edge_count[nr],
						__ATOMIC_RELAXED);

					output(0, "  %-24s %10lu %10lu %10lu %10lu %10lu %10lu\n",
					       name, lc, lec, len_, rc, rec, ren);
				}
			}
		}
		{
			unsigned int lr_top_op[10];
			unsigned long lr_top_total[10];
			unsigned int lr_top_count = 0;
			unsigned int op;

			memset(lr_top_total, 0, sizeof(lr_top_total));
			for (op = 0; op < KCOV_CHILDOP_NR_MAX; op++) {
				unsigned long lc = __atomic_load_n(
					&kcov_shm->childop_local_pc_calls[op],
					__ATOMIC_RELAXED);
				unsigned long rc = __atomic_load_n(
					&kcov_shm->childop_remote_pc_calls[op],
					__ATOMIC_RELAXED);
				unsigned long tot = lc + rc;

				if (tot == 0)
					continue;
				topn_push(lr_top_total, lr_top_op,
					  &lr_top_count, 10, tot, op);
			}
			if (lr_top_count > 0) {
				output(0, "Local vs remote PC yield per childop (top by combined calls):\n");
				output(0, "  %-24s %10s %10s %10s %10s %10s %10s\n",
				       "childop",
				       "loc_calls", "loc_eCalls", "loc_eCount",
				       "rem_calls", "rem_eCalls", "rem_eCount");
				for (j = 0; j < lr_top_count; j++) {
					unsigned int op_id = lr_top_op[j];
					char opname[64];
					unsigned long lc = __atomic_load_n(
						&kcov_shm->childop_local_pc_calls[op_id],
						__ATOMIC_RELAXED);
					unsigned long lec = __atomic_load_n(
						&kcov_shm->childop_local_pc_edge_calls[op_id],
						__ATOMIC_RELAXED);
					unsigned long len_ = __atomic_load_n(
						&kcov_shm->childop_local_pc_edge_count[op_id],
						__ATOMIC_RELAXED);
					unsigned long rc = __atomic_load_n(
						&kcov_shm->childop_remote_pc_calls[op_id],
						__ATOMIC_RELAXED);
					unsigned long rec = __atomic_load_n(
						&kcov_shm->childop_remote_pc_edge_calls[op_id],
						__ATOMIC_RELAXED);
					unsigned long ren = __atomic_load_n(
						&kcov_shm->childop_remote_pc_edge_count[op_id],
						__ATOMIC_RELAXED);

					snprintf(opname, sizeof(opname), "%s",
						 alt_op_name((enum child_op_type)op_id));
					output(0, "  %-24s %10lu %10lu %10lu %10lu %10lu %10lu\n",
					       opname, lc, lec, len_, rc, rec, ren);
				}
			}
		}

		/* Per-syscall + per-childop view of remote-edge yield,
		 * sorted by REMOTE edge count.  The combined-calls block
		 * above ranks by traffic; this one ranks by what actually
		 * fell out of remote-mode collection so the operator can
		 * see which slots are paying the cost of remote sampling
		 * vs. which are silent on that arm.  Render-only over the
		 * existing per_syscall/childop local|remote counters.  The
		 * flag column tags rows whose remote eCount is >= 50% of
		 * the leader across both sub-tables (HEAVY); the rate
		 * columns show local and remote edge-call yield (edge
		 * calls per call). */
		{
			unsigned int re_top_nr[10];
			unsigned long re_top_rec[10];
			unsigned int re_top_count = 0;
			unsigned int op_top_id[10];
			unsigned long op_top_rec[10];
			unsigned int op_top_count = 0;
			unsigned long max_rec = 0;
			unsigned int op;

			memset(re_top_rec, 0, sizeof(re_top_rec));
			memset(op_top_rec, 0, sizeof(op_top_rec));

			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long rec = __atomic_load_n(
					&kcov_shm->remote_pc_edge_count[i],
					__ATOMIC_RELAXED);

				if (rec == 0)
					continue;
				if (rec > max_rec)
					max_rec = rec;
				topn_push(re_top_rec, re_top_nr,
					  &re_top_count, 10, rec, i);
			}
			for (op = 0; op < KCOV_CHILDOP_NR_MAX; op++) {
				unsigned long rec = __atomic_load_n(
					&kcov_shm->childop_remote_pc_edge_count[op],
					__ATOMIC_RELAXED);

				if (rec == 0)
					continue;
				if (rec > max_rec)
					max_rec = rec;
				topn_push(op_top_rec, op_top_id,
					  &op_top_count, 10, rec, op);
			}

			if (re_top_count > 0 || op_top_count > 0) {
				output(0, "Top remote-edge producers (by rem_eCount):\n");
				output(0, "  %-2s %-24s %10s %10s %10s %10s %10s %10s %6s %6s\n",
				       "fl", "entry",
				       "loc_calls", "loc_eCalls", "loc_eCount",
				       "rem_calls", "rem_eCalls", "rem_eCount",
				       "loc_r", "rem_r");
			}

			for (j = 0; j < re_top_count; j++) {
				struct syscallentry *entry =
					table[re_top_nr[j]].entry;
				const char *name = entry ? entry->name : "???";
				unsigned int nr = re_top_nr[j];
				unsigned long lc = __atomic_load_n(
					&kcov_shm->local_pc_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long lec = __atomic_load_n(
					&kcov_shm->local_pc_edge_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long len_ = __atomic_load_n(
					&kcov_shm->local_pc_edge_count[nr],
					__ATOMIC_RELAXED);
				unsigned long rc = __atomic_load_n(
					&kcov_shm->remote_pc_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long rec = __atomic_load_n(
					&kcov_shm->remote_pc_edge_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long ren = re_top_rec[j];
				char fbuf[4], lrate[8], rrate[8];

				remote_edge_row_flags(fbuf, sizeof(fbuf),
						      ren, max_rec);
				remote_edge_format_yield(lrate, sizeof(lrate),
							 lec, lc);
				remote_edge_format_yield(rrate, sizeof(rrate),
							 rec, rc);
				output(0, "  %-2s %-24s %10lu %10lu %10lu %10lu %10lu %10lu %6s %6s\n",
				       fbuf, name, lc, lec, len_,
				       rc, rec, ren, lrate, rrate);
			}
			for (j = 0; j < op_top_count; j++) {
				unsigned int op_id = op_top_id[j];
				const char *opname = alt_op_name(
					(enum child_op_type)op_id);
				unsigned long lc = __atomic_load_n(
					&kcov_shm->childop_local_pc_calls[op_id],
					__ATOMIC_RELAXED);
				unsigned long lec = __atomic_load_n(
					&kcov_shm->childop_local_pc_edge_calls[op_id],
					__ATOMIC_RELAXED);
				unsigned long len_ = __atomic_load_n(
					&kcov_shm->childop_local_pc_edge_count[op_id],
					__ATOMIC_RELAXED);
				unsigned long rc = __atomic_load_n(
					&kcov_shm->childop_remote_pc_calls[op_id],
					__ATOMIC_RELAXED);
				unsigned long rec = __atomic_load_n(
					&kcov_shm->childop_remote_pc_edge_calls[op_id],
					__ATOMIC_RELAXED);
				unsigned long ren = op_top_rec[j];
				char fbuf[4], lrate[8], rrate[8];

				remote_edge_row_flags(fbuf, sizeof(fbuf),
						      ren, max_rec);
				remote_edge_format_yield(lrate, sizeof(lrate),
							 lec, lc);
				remote_edge_format_yield(rrate, sizeof(rrate),
							 rec, rc);
				output(0, "  %-2s %-24s %10lu %10lu %10lu %10lu %10lu %10lu %6s %6s\n",
				       fbuf, opname, lc, lec, len_,
				       rc, rec, ren, lrate, rrate);
			}
		}

		/* Per-syscall view of slots whose edge-producing calls
		 * arrived EXCLUSIVELY on the remote arm (loc_eCalls == 0
		 * && rem_eCalls > 0), sorted by remote edges per remote
		 * edge-producing call.  The rem_eCount-ranked block above
		 * pulls in any slot the remote arm produces on, including
		 * the ones the local arm also finds, so a slot whose
		 * entire edge signal comes from remote sampling can be
		 * drowned out there.  This block lists those slots in
		 * isolation and orders by yield density (rem_eCount /
		 * rem_eCalls), giving a direct read on which
		 * exclusively-remote syscalls are paying for the cost of
		 * remote-mode collection.  Render-only over the existing
		 * per-syscall local|remote counters; no new shm. */
		{
			unsigned int ro_top_nr[10];
			unsigned long ro_top_rate[10];
			unsigned int ro_top_count = 0;

			memset(ro_top_rate, 0, sizeof(ro_top_rate));

			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long lec = __atomic_load_n(
					&kcov_shm->local_pc_edge_calls[i],
					__ATOMIC_RELAXED);
				unsigned long rec = __atomic_load_n(
					&kcov_shm->remote_pc_edge_calls[i],
					__ATOMIC_RELAXED);
				unsigned long ren, rate;

				if (lec != 0 || rec == 0)
					continue;
				ren = __atomic_load_n(
					&kcov_shm->remote_pc_edge_count[i],
					__ATOMIC_RELAXED);
				/* rec > 0 here; ren >= rec by
				 * construction so rate is >= 1.000. */
				rate = (ren * 1000UL) / rec;
				topn_push(ro_top_rate, ro_top_nr,
					  &ro_top_count, 10, rate, i);
			}

			if (ro_top_count > 0) {
				output(0, "Remote-only edge winners (by rem_eCount/rem_eCalls):\n");
				output(0, "  %-24s %10s %10s %10s %10s %8s\n",
				       "syscall", "loc_calls", "rem_calls",
				       "rem_eCalls", "rem_eCount", "rate");
				for (j = 0; j < ro_top_count; j++) {
					struct syscallentry *entry =
						table[ro_top_nr[j]].entry;
					const char *name = entry ? entry->name : "???";
					unsigned int nr = ro_top_nr[j];
					unsigned long milli = ro_top_rate[j];
					unsigned long lc = __atomic_load_n(
						&kcov_shm->local_pc_calls[nr],
						__ATOMIC_RELAXED);
					unsigned long rc = __atomic_load_n(
						&kcov_shm->remote_pc_calls[nr],
						__ATOMIC_RELAXED);
					unsigned long rec = __atomic_load_n(
						&kcov_shm->remote_pc_edge_calls[nr],
						__ATOMIC_RELAXED);
					unsigned long ren = __atomic_load_n(
						&kcov_shm->remote_pc_edge_count[nr],
						__ATOMIC_RELAXED);

					output(0, "  %-24s %10lu %10lu %10lu %10lu %4lu.%03lu\n",
					       name, lc, rc, rec, ren,
					       milli / 1000, milli % 1000);
				}
			}
		}

		/* Per-syscall remote-enable health, sorted by the
		 * req - succ gap.  The four counters partition the
		 * kcov_enable_remote() path itself: requested is
		 * bumped once control is past the early-out and the
		 * KCOV_REMOTE_ENABLE ioctl is about to be attempted;
		 * succeeded once that ioctl returns 0; failed once
		 * it exhausts its EINTR retries or returns a
		 * non-EINTR error and flips remote_capable=false;
		 * remote_fallback_to_local once the PC-mode fallback
		 * ioctl that follows such a failure itself
		 * succeeds.  The yield-side local|remote split
		 * blocks above can only fold a refused remote enable
		 * into the local-mode column (the same child still
		 * produced PC-mode coverage via fallback), so a
		 * HEAVY-flagged slot whose KCOV_REMOTE_ENABLE
		 * consistently fails reads there as "zero remote
		 * yield" indistinguishable from "remote was sampled
		 * and the kernel ran the work on the calling task".
		 * Looking at req - succ directly per syscall surfaces
		 * the refusal surface the yield columns hide.
		 * Render-only over the existing per-syscall counters
		 * declared in include/kcov.h; no new shm, no
		 * behaviour change. */
		{
			unsigned int re_top_nr[10];
			unsigned long re_top_gap[10];
			unsigned int re_top_count = 0;

			memset(re_top_gap, 0, sizeof(re_top_gap));

			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long req = __atomic_load_n(
					&kcov_shm->remote_enable_requested[i],
					__ATOMIC_RELAXED);
				unsigned long succ;
				unsigned long gap;

				if (req == 0)
					continue;
				succ = __atomic_load_n(
					&kcov_shm->remote_enable_succeeded[i],
					__ATOMIC_RELAXED);
				/* req and succ are bumped on separate
				 * RELAXED stores in kcov_enable_remote();
				 * under pressure a reader can sample
				 * succ ahead of its matching req bump.
				 * Clamp the unsigned subtraction so a
				 * torn sample never wraps to ~ULONG_MAX. */
				gap = succ >= req ? 0 : req - succ;
				topn_push(re_top_gap, re_top_nr,
					  &re_top_count, 10, gap, i);
			}

			if (re_top_count > 0) {
				output(0, "Per-syscall remote-enable health (by req-succ gap):\n");
				output(0, "  %-24s %10s %10s %10s %10s %10s %8s\n",
				       "syscall", "req", "succ", "fail",
				       "fb_loc", "gap", "gRate");
				for (j = 0; j < re_top_count; j++) {
					struct syscallentry *entry =
						table[re_top_nr[j]].entry;
					const char *name = entry ? entry->name : "???";
					unsigned int nr = re_top_nr[j];
					unsigned long req = __atomic_load_n(
						&kcov_shm->remote_enable_requested[nr],
						__ATOMIC_RELAXED);
					unsigned long succ = __atomic_load_n(
						&kcov_shm->remote_enable_succeeded[nr],
						__ATOMIC_RELAXED);
					unsigned long fail = __atomic_load_n(
						&kcov_shm->remote_enable_failed[nr],
						__ATOMIC_RELAXED);
					unsigned long fbl = __atomic_load_n(
						&kcov_shm->remote_fallback_to_local[nr],
						__ATOMIC_RELAXED);
					unsigned long gap = succ >= req ? 0 : req - succ;
					unsigned long milli = (gap * 1000UL) / req;

					output(0, "  %-24s %10lu %10lu %10lu %10lu %10lu %4lu.%03lu\n",
					       name, req, succ, fail, fbl, gap,
					       milli / 1000, milli % 1000);
				}
			}
		}

		/* Per-syscall view of slots whose remote-mode enable was
		 * attempted at least REMOTE_WASTE_FLOOR times yet produced
		 * zero remote edges, sorted by remote-enable requested.
		 * The rem_eCount-ranked and remote-only views above pull
		 * in slots that DO yield on the remote arm; this block is
		 * the inverse cut, lifting out the slots where remote
		 * sampling has paid its KCOV_REMOTE_ENABLE / disable
		 * round-trip cost enough times to be statistically
		 * meaningful and earned nothing back, so the operator can
		 * read the demote-candidate list directly.  HEAVY is
		 * surfaced in its own column because the same condition
		 * on a HEAVY-flagged syscall is the loudest signal: the
		 * syscall is paying the heavier sampling rate and still
		 * carrying zero remote yield.  The waste verdict gates on
		 * remote_enable_requested (bumped on entry to the
		 * KCOV_REMOTE_ENABLE attempt) rather than remote_pc_calls
		 * (bumped only on a successful collect) so a syscall whose
		 * enable consistently falls back to local-mode PC coverage
		 * is not hidden by its own refusal surface; succ and fail
		 * are printed alongside so a "wasted" reading can be split
		 * into "sampled enough and produced no edge" vs "rarely
		 * even successfully sampled".  Render-only over the
		 * existing per-syscall counters declared in include/kcov.h;
		 * no new shm, no behaviour change to the collection or
		 * fuzzing path.  No childop variant: the per-childop
		 * remote-enable counters the verdict needs do not exist
		 * (childop enable accounting was intentionally deferred). */
		{
			unsigned int w_top_nr[10];
			unsigned long w_top_req[10];
			unsigned int w_top_count = 0;

			memset(w_top_req, 0, sizeof(w_top_req));

			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long req = __atomic_load_n(
					&kcov_shm->remote_enable_requested[i],
					__ATOMIC_RELAXED);
				unsigned long rec;

				if (req < REMOTE_WASTE_FLOOR)
					continue;
				rec = __atomic_load_n(
					&kcov_shm->remote_pc_edge_calls[i],
					__ATOMIC_RELAXED);
				if (rec != 0)
					continue;
				topn_push(w_top_req, w_top_nr,
					  &w_top_count, 10, req, i);
			}

			if (w_top_count > 0) {
				output(0, "Wasted-remote syscalls (req >= %lu, rem_eCalls == 0):\n",
				       REMOTE_WASTE_FLOOR);
				output(0, "  %-2s %-24s %10s %10s %10s %10s %10s %10s\n",
				       "fl", "syscall",
				       "req", "succ", "fail", "fb_loc",
				       "rem_calls", "rem_eCount");
				for (j = 0; j < w_top_count; j++) {
					struct syscallentry *entry =
						table[w_top_nr[j]].entry;
					const char *name = entry ? entry->name : "???";
					unsigned int nr = w_top_nr[j];
					unsigned long req = w_top_req[j];
					unsigned long succ = __atomic_load_n(
						&kcov_shm->remote_enable_succeeded[nr],
						__ATOMIC_RELAXED);
					unsigned long fail = __atomic_load_n(
						&kcov_shm->remote_enable_failed[nr],
						__ATOMIC_RELAXED);
					unsigned long fbl = __atomic_load_n(
						&kcov_shm->remote_fallback_to_local[nr],
						__ATOMIC_RELAXED);
					unsigned long rc = __atomic_load_n(
						&kcov_shm->remote_pc_calls[nr],
						__ATOMIC_RELAXED);
					unsigned long ren = __atomic_load_n(
						&kcov_shm->remote_pc_edge_count[nr],
						__ATOMIC_RELAXED);
					bool heavy = entry &&
						(entry->flags & KCOV_REMOTE_HEAVY);

					output(0, "  %-2s %-24s %10lu %10lu %10lu %10lu %10lu %10lu\n",
					       heavy ? "H" : "-", name,
					       req, succ, fail, fbl, rc, ren);
				}
			}
		}

		/* combined top-N
		 * trace_truncated + cmp_trace_truncated + max_trace_size
		 * table plus a dedup-probe-overflow summary line.  Lets
		 * buffer-policy decisions read off the cross-counter signal
		 * (saturate-without-trunc vs trunc-with-modest-max) that
		 * the per-counter blocks below flatten.  Diagnostic only. */
		kcov_diag_emit_truncation_topn();

		/* Per-syscall KCOV diagnostic blocks.  See kcov_diag_emit_block:
		 * one top-20-non-zero block per counter, alphabetical by
		 * counter name, silent when no syscall has a non-zero
		 * value. */
		kcov_diag_emit_block("bucket_bits_real",
				     KCOV_DIAG_BUCKET_BITS_REAL);
		kcov_diag_emit_block("cmp_trace_truncated",
				     KCOV_DIAG_CMP_TRACE_TRUNCATED);
		kcov_diag_emit_block("dedup_probe_overflow",
				     KCOV_DIAG_DEDUP_PROBE_OVERFLOW);
		kcov_diag_emit_block("distinct_pcs",
				     KCOV_DIAG_DISTINCT_PCS);
		kcov_diag_emit_block("max_trace_size",
				     KCOV_DIAG_MAX_TRACE_SIZE);
		kcov_diag_emit_block("trace_truncated",
				     KCOV_DIAG_TRACE_TRUNCATED);
	}
}
