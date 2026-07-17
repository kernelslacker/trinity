#include <stddef.h>
#include "stats-internal.h"

/* --blob-ab-mode within-run A/B harness (default off, opt-in only).
 * Separate category so a run with --blob-mutator=havoc / cmpdict but
 * WITHOUT --blob-ab-mode does not render eight zero rows for the ab
 * counters.  Gate on blob_ab_havoc_fills: the harness coin-flips
 * 50/50, so at any observable run length both counters are non-zero
 * together; picking one for the gate suppresses the whole block on
 * every non-ab run.  Verdict per mode: hit_cmp / fills on warm /
 * PC-plateau runs (the fleet default -- new_edges is ~0 there),
 * new_edges / fills on cold runs.  sum_cmp is a non-gating shadow
 * (CMP-novelty magnitude) for diagnostics only, never the verdict.
 * Per-fill rates are the clean comparison because both arms share
 * the same warm corpus / kcov state at every moment. */
static const struct stat_field blob_ab_mode_fields[] = {
	STAT_FIELD(blob_ab, havoc_fills),
	STAT_FIELD(blob_ab, havoc_new_edges),
	STAT_FIELD(blob_ab, havoc_hit_cmp),
	STAT_FIELD(blob_ab, havoc_sum_cmp),
	STAT_FIELD(blob_ab, cmpdict_fills),
	STAT_FIELD(blob_ab, cmpdict_new_edges),
	STAT_FIELD(blob_ab, cmpdict_hit_cmp),
	STAT_FIELD(blob_ab, cmpdict_sum_cmp),
};

const struct stat_category blob_ab_mode_category =
	STAT_CATEGORY("blob_ab_mode",
	              blob_ab_havoc_fills,
	              blob_ab_mode_fields);

/*
 * Descriptors for dump_stats_json_oracle().  Every member is named
 * <syscall>_oracle_anomalies in struct stats_s but the JSON schema emits it
 * as "<syscall>_anomalies" (the "oracle_" infix is implicit in the enclosing
 * category key), so each row uses STAT_FIELD_JSON to pin the cross-prefix
 * JSON key.  The JSON walker ignores stat_category.gate_offset (it emits
 * every category unconditionally) and the text dump for oracle stays
 * hand-coded in dump_stats_oracle_anomalies() where each row has its own
 * per-field gate, so fd_oracle_anomalies here is a placeholder gate that
 * matters only if a future change wires stat_category_emit_text() onto this
 * table.
 */
static const struct stat_field oracle_fields[] = {
	STAT_FIELD_JSON(fd_oracle, anomalies, "fd_anomalies"),
	STAT_FIELD_JSON(mmap_oracle, anomalies, "mmap_anomalies"),
	STAT_FIELD_JSON(cred_oracle, anomalies, "cred_anomalies"),
	STAT_FIELD_JSON(sched_oracle, anomalies, "sched_anomalies"),
	STAT_FIELD_JSON(uid_oracle, anomalies, "uid_anomalies"),
	STAT_FIELD_JSON(gid_oracle, anomalies, "gid_anomalies"),
	STAT_FIELD_JSON(setgroups_oracle, anomalies, "setgroups_anomalies"),
	STAT_FIELD_JSON(getegid_oracle, anomalies, "getegid_anomalies"),
	STAT_FIELD_JSON(getuid_oracle, anomalies, "getuid_anomalies"),
	STAT_FIELD_JSON(getgid_oracle, anomalies, "getgid_anomalies"),
	STAT_FIELD_JSON(getppid_oracle, anomalies, "getppid_anomalies"),
	STAT_FIELD_JSON(getcwd_oracle, anomalies, "getcwd_anomalies"),
	STAT_FIELD_JSON(getpid_oracle, anomalies, "getpid_anomalies"),
	STAT_FIELD_JSON(getpgid_oracle, anomalies, "getpgid_anomalies"),
	STAT_FIELD_JSON(getpgrp_oracle, anomalies, "getpgrp_anomalies"),
	STAT_FIELD_JSON(geteuid_oracle, anomalies, "geteuid_anomalies"),
	STAT_FIELD_JSON(getsid_oracle, anomalies, "getsid_anomalies"),
	STAT_FIELD_JSON(gettid_oracle, anomalies, "gettid_anomalies"),
	STAT_FIELD_JSON(setsid_oracle, anomalies, "setsid_anomalies"),
	STAT_FIELD_JSON(setpgid_oracle, anomalies, "setpgid_anomalies"),
	STAT_FIELD_JSON(sched_getscheduler_oracle, anomalies, "sched_getscheduler_anomalies"),
	STAT_FIELD_JSON(getgroups_oracle, anomalies, "getgroups_anomalies"),
	STAT_FIELD_JSON(getresuid_oracle, anomalies, "getresuid_anomalies"),
	STAT_FIELD_JSON(getresgid_oracle, anomalies, "getresgid_anomalies"),
	STAT_FIELD_JSON(umask_oracle, anomalies, "umask_anomalies"),
	STAT_FIELD_JSON(sched_get_priority_max_oracle, anomalies, "sched_get_priority_max_anomalies"),
	STAT_FIELD_JSON(sched_get_priority_min_oracle, anomalies, "sched_get_priority_min_anomalies"),
	STAT_FIELD_JSON(sched_yield_oracle, anomalies, "sched_yield_anomalies"),
	STAT_FIELD_JSON(getpagesize_oracle, anomalies, "getpagesize_anomalies"),
	STAT_FIELD_JSON(time_oracle, anomalies, "time_anomalies"),
	STAT_FIELD_JSON(gettimeofday_oracle, anomalies, "gettimeofday_anomalies"),
	STAT_FIELD_JSON(newuname_oracle, anomalies, "newuname_anomalies"),
	STAT_FIELD_JSON(rt_sigpending_oracle, anomalies, "rt_sigpending_anomalies"),
	STAT_FIELD_JSON(sched_getaffinity_oracle, anomalies, "sched_getaffinity_anomalies"),
	STAT_FIELD_JSON(rt_sigprocmask_oracle, anomalies, "rt_sigprocmask_anomalies"),
	STAT_FIELD_JSON(sched_getparam_oracle, anomalies, "sched_getparam_anomalies"),
	STAT_FIELD_JSON(sched_rr_get_interval_oracle, anomalies, "sched_rr_get_interval_anomalies"),
	STAT_FIELD_JSON(get_robust_list_oracle, anomalies, "get_robust_list_anomalies"),
	STAT_FIELD_JSON(getrlimit_oracle, anomalies, "getrlimit_anomalies"),
	STAT_FIELD_JSON(sysinfo_oracle, anomalies, "sysinfo_anomalies"),
	STAT_FIELD_JSON(times_oracle, anomalies, "times_anomalies"),
	STAT_FIELD_JSON(clock_getres_oracle, anomalies, "clock_getres_anomalies"),
	STAT_FIELD_JSON(capget_oracle, anomalies, "capget_anomalies"),
	STAT_FIELD_JSON(capdrop_oracle, anomalies, "capdrop_anomalies"),
	STAT_FIELD_JSON(newlstat_oracle, anomalies, "newlstat_anomalies"),
	STAT_FIELD_JSON(newstat_oracle, anomalies, "newstat_anomalies"),
	STAT_FIELD_JSON(newfstat_oracle, anomalies, "newfstat_anomalies"),
	STAT_FIELD_JSON(newfstatat_oracle, anomalies, "newfstatat_anomalies"),
	STAT_FIELD_JSON(statx_oracle, anomalies, "statx_anomalies"),
	STAT_FIELD_JSON(fstatfs_oracle, anomalies, "fstatfs_anomalies"),
	STAT_FIELD_JSON(fstatfs64_oracle, anomalies, "fstatfs64_anomalies"),
	STAT_FIELD_JSON(statfs_oracle, anomalies, "statfs_anomalies"),
	STAT_FIELD_JSON(statfs64_oracle, anomalies, "statfs64_anomalies"),
	STAT_FIELD_JSON(uname_oracle, anomalies, "uname_anomalies"),
	STAT_FIELD_JSON(lsm_list_modules_oracle, anomalies, "lsm_list_modules_anomalies"),
	STAT_FIELD_JSON(listmount_oracle, anomalies, "listmount_anomalies"),
	STAT_FIELD_JSON(statmount_oracle, anomalies, "statmount_anomalies"),
	STAT_FIELD_JSON(getsockname_oracle, anomalies, "getsockname_anomalies"),
	STAT_FIELD_JSON(getpeername_oracle, anomalies, "getpeername_anomalies"),
	STAT_FIELD_JSON(file_getattr_oracle, anomalies, "file_getattr_anomalies"),
	STAT_FIELD_JSON(sched_getattr_oracle, anomalies, "sched_getattr_anomalies"),
	STAT_FIELD_JSON(getrusage_oracle, anomalies, "getrusage_anomalies"),
	STAT_FIELD_JSON(sigpending_oracle, anomalies, "sigpending_anomalies"),
	STAT_FIELD_JSON(getcpu_oracle, anomalies, "getcpu_anomalies"),
	STAT_FIELD_JSON(clock_gettime_oracle, anomalies, "clock_gettime_anomalies"),
	STAT_FIELD_JSON(get_mempolicy_oracle, anomalies, "get_mempolicy_anomalies"),
	STAT_FIELD_JSON(lsm_get_self_attr_oracle, anomalies, "lsm_get_self_attr_anomalies"),
	STAT_FIELD_JSON(prlimit64_oracle, anomalies, "prlimit64_anomalies"),
	STAT_FIELD_JSON(sigaltstack_oracle, anomalies, "sigaltstack_anomalies"),
	STAT_FIELD_JSON(olduname_oracle, anomalies, "olduname_anomalies"),
	STAT_FIELD_JSON(lookup_dcookie_oracle, anomalies, "lookup_dcookie_anomalies"),
	STAT_FIELD_JSON(getxattr_oracle, anomalies, "getxattr_anomalies"),
	STAT_FIELD_JSON(lgetxattr_oracle, anomalies, "lgetxattr_anomalies"),
	STAT_FIELD_JSON(fgetxattr_oracle, anomalies, "fgetxattr_anomalies"),
	STAT_FIELD_JSON(listxattrat_oracle, anomalies, "listxattrat_anomalies"),
	STAT_FIELD_JSON(flistxattr_oracle, anomalies, "flistxattr_anomalies"),
	STAT_FIELD_JSON(listxattr_oracle, anomalies, "listxattr_anomalies"),
	STAT_FIELD_JSON(llistxattr_oracle, anomalies, "llistxattr_anomalies"),
	STAT_FIELD_JSON(readlink_oracle, anomalies, "readlink_anomalies"),
	STAT_FIELD_JSON(readlinkat_oracle, anomalies, "readlinkat_anomalies"),
	STAT_FIELD_JSON(sysfs_oracle, anomalies, "sysfs_anomalies"),
};

const struct stat_category oracle_category =
	STAT_CATEGORY("oracle",
	              fd_oracle_anomalies,
	              oracle_fields);

/*
 * Descriptor tables staged for the follow-up JSON fan-out (per-fn conversions
 * of dump_stats_json_iouring_and_zombies / _socket_family_and_tls /
 * _iouring_zc_and_kvm / _netfilter_and_xfrm / _fault_and_fd_lifecycle).
 *
 * The category JSON key in each case doesn't match the struct member's
 * single prefix, so STAT_FIELD() rows pick whichever prefix matches the
 * actual struct member (packet_fanout_*, recipe_*, nat_t_churn_/nat_t_,
 * kvm_run_/kvm_, fd_/local_fd_/epoll_); .name doubles as the text-side
 * key.  For fd_lifecycle's three cross-prefix members (local_fd_* and
 * epoll_*) the suffix alone wouldn't yield the schema's JSON key, so
 * STAT_FIELD_JSON() pins the JSON key explicitly.
 *
 * As with the fs_lifecycle/futex_storm pair above, the JSON walker
 * ignores stat_category.gate_offset; the gate field is set to the same
 * counter the existing text emitter uses (or a placeholder for
 * fd_lifecycle, which has no single gate) so a future text-side wiring
 * has a sensible default.  These tables have no live caller yet -- they
 * land here so the per-fn JSON conversions can be reviewed in isolation.
 */
static const struct stat_field packet_fanout_thrash_fields[] = {
	STAT_FIELD(packet_fanout, runs),
	STAT_FIELD(packet_fanout, setup_failed),
	STAT_FIELD(packet_fanout, ring_failed),
	STAT_FIELD(packet_fanout, rings_installed),
	STAT_FIELD(packet_fanout, mmap_failed),
	STAT_FIELD(packet_fanout, joins),
	STAT_FIELD(packet_fanout, rejoins_ok),
	STAT_FIELD(packet_fanout, rejoins_rejected),
};

static const struct stat_category packet_fanout_thrash_category
	__attribute__((unused)) =
	STAT_CATEGORY("packet_fanout_thrash",
	              packet_fanout_runs,
	              packet_fanout_thrash_fields);

static const struct stat_field recipe_runner_fields[] = {
	STAT_FIELD(recipe, runs),
	STAT_FIELD(recipe, completed),
	STAT_FIELD(recipe, partial),
	STAT_FIELD(recipe, unsupported),
};

const struct stat_category recipe_runner_category =
	STAT_CATEGORY("recipe_runner",
	              recipe_runs,
	              recipe_runner_fields);

/*
 * Descriptors for the remaining categories in
 * dump_stats_json_iouring_and_zombies().  The text-side dump for these stays
 * hand-coded for now, and the JSON walker ignores gate_offset, so the gate
 * field choices below only matter if a future change wires
 * stat_category_emit_text() onto these tables.
 */
static const struct stat_field iouring_recipes_fields[] = {
	STAT_FIELD(iouring_recipes, runs),
	STAT_FIELD(iouring_recipes, completed),
	STAT_FIELD(iouring_recipes, partial),
	STAT_FIELD(iouring_recipes, enosys),
};

const struct stat_category iouring_recipes_category =
	STAT_CATEGORY("iouring_recipes",
	              iouring_recipes_runs,
	              iouring_recipes_fields);

static const struct stat_field iouring_eventfd_fields[] = {
	STAT_FIELD(iouring_eventfd, register_ok),
	STAT_FIELD(iouring_eventfd, register_fail),
	STAT_FIELD(iouring_eventfd, recursive_runs),
	STAT_FIELD(iouring_eventfd, recursive_cqes),
};

const struct stat_category iouring_eventfd_category =
	STAT_CATEGORY("iouring_eventfd",
	              iouring_eventfd_register_ok,
	              iouring_eventfd_fields);

/* errno_gradient: SHADOW measurement of upward errno-class crossings (no
 * fuzzer-behaviour change -- see the errno_gradient_* block in
 * include/stats.h for the class axis and the SHADOW contract).  Aggregate
 * scalars only; the per-syscall last-class array is deliberately
 * unrendered (internal to the predicate, matching the other per-syscall
 * shadow arrays).  Text render gates on errno_gradient_crossings so a
 * run that never observed an upward transition emits nothing in the
 * text dump; JSON renders unconditionally for schema stability,
 * matching the aio sibling above. */
static const struct stat_field errno_gradient_fields[] = {
	STAT_FIELD(errno_gradient, crossings),
	STAT_FIELD(errno_gradient, to_permstate),
	STAT_FIELD(errno_gradient, to_success),
};

const struct stat_category errno_gradient_category =
	STAT_CATEGORY("errno_gradient",
	              errno_gradient_crossings,
	              errno_gradient_fields);

/* cold_overflow: SHADOW measurement of would-save events that fall on the
 * cold-or-corpus-absent tail under a CMP_RISING_PC_FLAT plateau (no
 * fuzzer-behaviour change -- see the cold_overflow_would_save_* block
 * in include/stats.h for the predicate and the SHADOW contract).
 * Aggregate scalars only.  Text render gates on cold_overflow_would_
 * save so a run that never observed a qualifying event emits nothing
 * in the text dump; JSON renders unconditionally for schema stability,
 * matching the errno_gradient sibling above. */
static const struct stat_field cold_overflow_fields[] = {
	STAT_FIELD(cold_overflow, would_save),
	STAT_FIELD(cold_overflow, would_save_cold),
	STAT_FIELD(cold_overflow, would_save_absent),
};

const struct stat_category cold_overflow_category =
	STAT_CATEGORY("cold_overflow",
	              cold_overflow_would_save,
	              cold_overflow_fields);

/* inplace_crypto_mutated: the inplace-crypto oracle childop overwrites a
 * plaintext slot mid-flight to catch handlers that read after the kernel
 * has copied; the per-mutation bump is the only positive signal that the
 * oracle ran productively in a window.  A single-field category renders
 * it in both JSON and text so a quiet "no mutations" window is
 * distinguishable from a window where the childop never fired. */
static const struct stat_field inplace_crypto_fields[] = {
	STAT_FIELD(inplace_crypto, mutated),
};

const struct stat_category inplace_crypto_category =
	STAT_CATEGORY("inplace_crypto",
	              inplace_crypto_mutated,
	              inplace_crypto_fields);

/* fd_runtime_skipped: handle_retval_obj_fd's post-success classify of an
 * fd retval against the per-child local-object table.  The two paths are
 * mutually exclusive per call and both increment from the same site, so a
 * run where neither bumped means no syscall ever produced a registerable
 * fd; gating on _stdio (the dominant arm — retvals 0/1/2 from any
 * fd-returning syscall) keeps a quiet window terse in the text dump.
 * JSON renders unconditionally alongside aio for schema stability. */
static const struct stat_field fd_runtime_skipped_fields[] = {
	STAT_FIELD(fd_runtime_skipped, stdio),
	STAT_FIELD(fd_runtime_skipped, already_registered),
};

const struct stat_category fd_runtime_skipped_category =
	STAT_CATEGORY("fd_runtime_skipped",
	              fd_runtime_skipped_stdio,
	              fd_runtime_skipped_fields);

/* child_dead_parent_observed: init_child()'s pid-handshake loop saw
 * pid_alive(mainpid) == false -- the parent died before publishing this
 * child's slot in pids[].  The original outputerr("BUG!: parent went
 * away!") was swallowed by the dup2 /dev/null redirect; a single-field
 * category surfaces the survivor signal in both dumps.  Text self-gates
 * so a healthy run emits nothing. */
static const struct stat_field child_fields[] = {
	STAT_FIELD(child, dead_parent_observed),
};

const struct stat_category child_category =
	STAT_CATEGORY("child",
	              child_dead_parent_observed,
	              child_fields);

/* parent_inherited_fds_closed: sanitize_inherited_fds() closed an fd
 * the parent inherited from its launcher (or the launcher's parent) at
 * startup.  Non-zero means the parent came in with stray fds beyond
 * {0,1,2}, which could otherwise wedge the reap-path epoll/poll loop.
 * A single-field category surfaces the cleanup count in both dumps;
 * text self-gates so a clean launch environment emits nothing. */
static const struct stat_field parent_fields[] = {
	STAT_FIELD(parent, inherited_fds_closed),
};

const struct stat_category parent_category =
	STAT_CATEGORY("parent",
	              parent_inherited_fds_closed,
	              parent_fields);

/* uid_change_logged: check_uid saw the child's uid drift away from
 * orig_uid + overflowuid.  Non-root drifts log-and-continue rather than
 * hard-bailing, so the drift count is the only positive signal that a
 * fuzzed setresuid/setreuid/setfsuid landed inside an unshared user
 * namespace.  A single-field category surfaces the count in both dumps;
 * text self-gates so a stable-uid run emits nothing. */
static const struct stat_field uid_change_fields[] = {
	STAT_FIELD(uid_change, logged),
};

const struct stat_category uid_change_category =
	STAT_CATEGORY("uid_change",
	              uid_change_logged,
	              uid_change_fields);

/* no_domains_runtime_skipped: socket families auto-marked in no_domains[]
 * at startup because socket() probes returned EAFNOSUPPORT/EPROTONOSUPPORT
 * for both SOCK_STREAM and SOCK_DGRAM.  Non-zero tells the operator how
 * many random-syscall socket() picks per cycle the running kernel can
 * never reach, and confirms the auto-skip ran (vs. --exclude-domains by
 * hand).  Text self-gates so a fully-supported build emits nothing. */
static const struct stat_field no_domains_fields[] = {
	STAT_FIELD(no_domains, runtime_skipped),
};

const struct stat_category no_domains_category =
	STAT_CATEGORY("no_domains",
	              no_domains_runtime_skipped,
	              no_domains_fields);

/* zombie_slots mixes two struct prefixes (zombie_slots_ for the gauge,
 * zombies_ for the counters); each STAT_FIELD picks its own prefix so the
 * JSON keys stay flat ("pending", "reaped", "timed_out"). */
static const struct stat_field zombie_slots_fields[] = {
	STAT_FIELD(zombie_slots, pending),
	STAT_FIELD(zombies, reaped),
	STAT_FIELD(zombies, timed_out),
};

const struct stat_category zombie_slots_category =
	STAT_CATEGORY("zombie_slots",
	              zombies_reaped,
	              zombie_slots_fields);

static const struct stat_field nat_t_churn_fields[] = {
	STAT_FIELD(nat_t_churn, runs),
	STAT_FIELD(nat_t_churn, setup_failed),
	STAT_FIELD(nat_t_churn, sa_added),
	STAT_FIELD(nat_t_churn, sa_deleted),
	STAT_FIELD(nat_t_churn, frames_sent),
	STAT_FIELD(nat_t, xfrm6_setup_ok),
	STAT_FIELD(nat_t, xfrm6_setup_fail),
	STAT_FIELD(nat_t, xfrm6_sendto_runs),
	STAT_FIELD(nat_t, xfrm6_delsa_races),
};

static const struct stat_category nat_t_churn_category
	__attribute__((unused)) =
	STAT_CATEGORY("nat_t_churn",
	              nat_t_churn_runs,
	              nat_t_churn_fields);

static const struct stat_field kvm_run_churn_fields[] = {
	STAT_FIELD(kvm_run, invocations),
	STAT_FIELD(kvm_run, exit_io),
	STAT_FIELD(kvm_run, exit_mmio),
	STAT_FIELD(kvm_run, exit_hlt),
	STAT_FIELD(kvm_run, exit_shutdown),
	STAT_FIELD(kvm_run, exit_fail_entry),
	STAT_FIELD(kvm_run, exit_internal_error),
	STAT_FIELD(kvm_run, exit_intr),
	STAT_FIELD(kvm_run, exit_other),
	STAT_FIELD(kvm_run, errors),
	STAT_FIELD(kvm, gpc_memslot_race_runs),
	STAT_FIELD(kvm, gpc_memslot_race_deletes),
	STAT_FIELD(kvm, gpc_memslot_race_unsupported),
};

static const struct stat_category kvm_run_churn_category
	__attribute__((unused)) =
	STAT_CATEGORY("kvm_run_churn",
	              kvm_run_invocations,
	              kvm_run_churn_fields);

static const struct stat_field fd_lifecycle_fields[] = {
	STAT_FIELD(fd, stale_detected),
	STAT_FIELD(fd, stale_by_generation),
	STAT_FIELD(fd, closed_tracked),
	STAT_FIELD(fd, duped),
	STAT_FIELD(fd, events_processed),
	STAT_FIELD(fd, events_dropped),
	STAT_FIELD(fd, event_close_count),
	STAT_FIELD(fd, event_evict_count),
	STAT_FIELD(fd, hash_reinsert_dropped),
	STAT_FIELD_JSON(local_fd, hash_insert_dropped,
	                "local_hash_insert_dropped"),
	STAT_FIELD(fd, runtime_registered),
	STAT_FIELD_JSON(epoll, lazy_armed, "epoll_lazy_armed"),
	STAT_FIELD_JSON(epoll, blocking_poll_skipped,
	                "epoll_blocking_poll_skipped"),
	STAT_FIELD(fd, random_exhausted),
	STAT_FIELD(fd, provider_invalid),
};

/* fd_lifecycle has no single gate counter -- the text emitter ORs many
 * fields.  Use fd_stale_detected as a placeholder for the JSON walker
 * (which ignores gate_offset); any text-side wiring will need to revisit. */
static const struct stat_category fd_lifecycle_category
	__attribute__((unused)) =
	STAT_CATEGORY("fd_lifecycle",
	              fd_stale_detected,
	              fd_lifecycle_fields);








