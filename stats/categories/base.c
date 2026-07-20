#include <stddef.h>
#include "stats-internal.h"

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
	STAT_FIELD_JSON_SUB(epoll_volatility, lazy_armed, "epoll_lazy_armed"),
	STAT_FIELD_JSON_SUB(epoll_volatility, blocking_poll_skipped,
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

