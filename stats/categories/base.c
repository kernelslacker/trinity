#include <stddef.h>
#include "stats-internal.h"

/*
 * Descriptor tables behind the JSON sections of
 * dump_stats_json_iouring_and_zombies() and
 * dump_stats_json_fault_and_fd_lifecycle().
 *
 * The category JSON key in each case doesn't match the struct member's
 * single prefix, so rows pick whichever sub-struct holds the member, and
 * STAT_FIELD_JSON_SUB() pins the JSON key where the suffix alone wouldn't
 * yield the schema's; .name doubles as the text-side key.
 *
 * stat_category_emit_text() emits the block when any field in the category
 * is non-zero.  These tables have no live text caller.
 */
/* child_dead_parent_observed: init_child()'s pid-handshake loop saw
 * pid_alive(mainpid) == false -- the parent died before publishing this
 * child's slot in pids[].  The original outputerr("BUG!: parent went
 * away!") was swallowed by the dup2 /dev/null redirect; a single-field
 * category surfaces the survivor signal in both dumps.  Text self-gates
 * so a healthy run emits nothing. */
static const struct stat_field child_fields[] = {
	STAT_FIELD_JSON_SUB(diag, child_dead_parent_observed, "dead_parent_observed"),
};

const struct stat_category child_category =
	STAT_CATEGORY("child",
	              child_fields);

/* parent_inherited_fds_closed: sanitize_inherited_fds() closed an fd
 * the parent inherited from its launcher (or the launcher's parent) at
 * startup.  Non-zero means the parent came in with stray fds beyond
 * {0,1,2}, which could otherwise wedge the reap-path epoll/poll loop.
 * A single-field category surfaces the cleanup count in both dumps;
 * text self-gates so a clean launch environment emits nothing. */
static const struct stat_field parent_fields[] = {
	STAT_FIELD_JSON_SUB(fd, parent_inherited_fds_closed,
	                    "inherited_fds_closed"),
};

const struct stat_category parent_category =
	STAT_CATEGORY("parent",
	              parent_fields);

/* zombie_slots mixes two struct prefixes (zombie_slots_ for the gauge,
 * zombies_ for the counters); each STAT_FIELD picks its own prefix so the
 * JSON keys stay flat ("pending", "reaped", "timed_out"). */
static const struct stat_field zombie_slots_fields[] = {
	STAT_FIELD_JSON_SUB(zombie_reaper, slots_pending, "pending"),
	STAT_FIELD_JSON_SUB(zombie_reaper, reaped, "reaped"),
	STAT_FIELD_JSON_SUB(zombie_reaper, timed_out, "timed_out"),
	STAT_FIELD_JSON_SUB(zombie_reaper, quarantined, "quarantined"),
};

const struct stat_category zombie_slots_category =
	STAT_CATEGORY("zombie_slots",
	              zombie_slots_fields);

static const struct stat_field fd_lifecycle_fields[] = {
	STAT_FIELD_SUB(fd, stale_detected),
	STAT_FIELD_SUB(fd, stale_by_generation),
	STAT_FIELD_SUB(fd, closed_tracked),
	STAT_FIELD_SUB(fd, duped),
	STAT_FIELD_SUB(fd, events_processed),
	STAT_FIELD_SUB(fd, events_dropped),
	STAT_FIELD_SUB(fd, event_close_count),
	STAT_FIELD_SUB(fd, event_evict_count),
	STAT_FIELD_SUB(fd, watchdog_evict_count),
	STAT_FIELD_SUB(fd, hash_reinsert_dropped),
	STAT_FIELD_SUB(fd, local_hash_insert_dropped),
	STAT_FIELD_JSON_SUB(fd_runtime, registered, "runtime_registered"),
	STAT_FIELD_JSON_SUB(epoll_volatility, lazy_armed, "epoll_lazy_armed"),
	STAT_FIELD_JSON_SUB(epoll_volatility, blocking_poll_skipped,
	                "epoll_blocking_poll_skipped"),
	STAT_FIELD_SUB(fd, random_exhausted),
	STAT_FIELD_SUB(fd, provider_invalid),
	STAT_FIELD_SUB(fd, live_remove_calls),
	STAT_FIELD_SUB(fd, live_remove_miss),
	{ .name = "live_remove_scan_histogram", .n_elems = 8,
	  .offset = offsetof(struct stats_s, fd.live_remove_scan_histogram) },
	STAT_FIELD_SUB(fd, event_full_close),
	STAT_FIELD_SUB(fd, event_full_evict),
	STAT_FIELD_SUB(fd, event_full_close_range),
	STAT_FIELD_SUB(fd, event_close_range_enqueued),
	STAT_FIELD_SUB(fd, event_close_range_length_sum),
};

/* fd_lifecycle has no single natural gate counter; stat_category_emit_text()
 * will emit the block when any field is non-zero, which covers the
 * ORed-fields case automatically. */
const struct stat_category fd_lifecycle_category =
	STAT_CATEGORY("fd_lifecycle",
	              fd_lifecycle_fields);

