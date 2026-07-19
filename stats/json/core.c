/*
 * Core (non-network) JSON section emitters for --stats-json.
 * Covers fault-injection, fd-lifecycle, oracle, basic
 * subsystems (vfs / memory-pressure / numa / netlink families /
 * tracefs / bpf), iouring / zombie, corruption / audit, and
 * fs-lifecycle / futex-storm.  The eight basic-subsystem
 * descriptor tables live here rather than under
 * stats/categories/ because they are still JSON-only consumers.
 */

#include <stdio.h>
#include <stddef.h>
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats/json/internal.h"
#include "stats_ring.h"
#include "trinity.h"

/*
 * Emit every counter from struct stats_s as a single JSON object.
 * All scalar counters are emitted unconditionally so consumers see a stable
 * schema regardless of which subsystems happened to fire on this run.
 */
void dump_stats_json_fault_and_fd_lifecycle(void)
{
	printf("\"fault_injection\":{\"armed_fail_nth\":%lu,\"returned_enomem\":%lu},"
		"\"fd_lifecycle\":{\"stale_detected\":%lu,\"stale_by_generation\":%lu,"
			"\"closed_tracked\":%lu,\"duped\":%lu,"
			"\"events_processed\":%lu,\"events_dropped\":%lu,"
			"\"event_close_count\":%lu,\"event_evict_count\":%lu,"
			"\"hash_reinsert_dropped\":%lu,"
			"\"local_hash_insert_dropped\":%lu,"
			"\"runtime_registered\":%lu,\"epoll_lazy_armed\":%lu,"
			"\"epoll_blocking_poll_skipped\":%lu,"
			"\"random_exhausted\":%lu,"
			"\"provider_invalid\":%lu,"
			"\"live_remove_calls\":%lu,"
			"\"live_remove_miss\":%lu,"
			"\"live_remove_scan_histogram\":[%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu],"
			"\"event_full_close\":%lu,"
			"\"event_full_evict\":%lu,"
			"\"event_full_close_range\":%lu,"
			"\"event_close_range_enqueued\":%lu,"
			"\"event_close_range_length_sum\":%lu},",
		parent_stats.fault_injected, parent_stats.fault_consumed,
		shm->stats.fd_stale_detected, shm->stats.fd_stale_by_generation,
		shm->stats.fd_closed_tracked,
		shm->stats.fd_duped, shm->stats.fd_events_processed,
		shm->stats.fd_events_dropped,
		shm->stats.fd_event_close_count, shm->stats.fd_event_evict_count,
		shm->stats.fd_hash_reinsert_dropped,
		shm->stats.local_fd_hash_insert_dropped,
		shm->stats.fd_runtime_registered,
		shm->stats.epoll_lazy_armed,
		shm->stats.epoll_blocking_poll_skipped,
		shm->stats.fd_random_exhausted,
		shm->stats.fd_provider_invalid,
		shm->stats.fd.live_remove_calls,
		shm->stats.fd.live_remove_miss,
		shm->stats.fd.live_remove_scan_histogram[0],
		shm->stats.fd.live_remove_scan_histogram[1],
		shm->stats.fd.live_remove_scan_histogram[2],
		shm->stats.fd.live_remove_scan_histogram[3],
		shm->stats.fd.live_remove_scan_histogram[4],
		shm->stats.fd.live_remove_scan_histogram[5],
		shm->stats.fd.live_remove_scan_histogram[6],
		shm->stats.fd.live_remove_scan_histogram[7],
		shm->stats.fd.event_full_close,
		shm->stats.fd.event_full_evict,
		shm->stats.fd.event_full_close_range,
		shm->stats.fd.event_close_range_enqueued,
		shm->stats.fd.event_close_range_length_sum);
}

void dump_stats_json_oracle(void)
{
	stat_category_emit_json(&oracle_category);
	putchar(',');
}

/*
 * Descriptor tables for dump_stats_json_basic_subsystems().
 *
 * The eight categories below were previously emitted by a single
 * hand-written printf with one %lu slot per field and a parallel
 * shm->stats.<field> va-list; adding a counter required three
 * correlated edits.  These tables collapse that to one STAT_FIELD*
 * row per field.
 *
 * The JSON walker ignores stat_category.gate_offset (every category
 * emits unconditionally), so the gate choices below only matter if a
 * future change wires stat_category_emit_text() onto these tables.
 * Each text-side block in dump_stats_text() stays hand-coded for now
 * and picks its own gate predicate.
 *
 * Where the JSON schema key doesn't match the struct member suffix
 * (vfs_writes, memory_pressure) the row uses STAT_FIELD_JSON to pin
 * the JSON key; .name still mirrors the struct suffix so the
 * descriptor stays self-consistent.  Those .name values do NOT match
 * the keys the hand-coded text emitter currently uses, so any future
 * text-side wiring onto these tables will need to revisit .name.
 */
static const struct stat_field vfs_writes_fields[] = {
	STAT_FIELD_JSON_SUB(procfs_writer, procfs_open_fail,   "procfs_open_fail"),
	STAT_FIELD_JSON_SUB(procfs_writer, procfs_write_fail,  "procfs_write_fail"),
	STAT_FIELD_JSON_SUB(procfs_writer, procfs_write_ok,    "procfs_write_ok"),
	STAT_FIELD_JSON_SUB(procfs_writer, sysfs_open_fail,    "sysfs_open_fail"),
	STAT_FIELD_JSON_SUB(procfs_writer, sysfs_write_fail,   "sysfs_write_fail"),
	STAT_FIELD_JSON_SUB(procfs_writer, sysfs_write_ok,     "sysfs_write_ok"),
	STAT_FIELD_JSON_SUB(procfs_writer, debugfs_open_fail,  "debugfs_open_fail"),
	STAT_FIELD_JSON_SUB(procfs_writer, debugfs_write_fail, "debugfs_write_fail"),
	STAT_FIELD_JSON_SUB(procfs_writer, debugfs_write_ok,   "debugfs_write_ok"),
};

const struct stat_category vfs_writes_category =
	STAT_CATEGORY("vfs_writes",
	              procfs_writer.procfs_open_fail,
	              vfs_writes_fields);

static const struct stat_field memory_pressure_fields[] = {
	STAT_FIELD_JSON(memory_pressure, runs, "runs_madv_pageout"),
};

const struct stat_category memory_pressure_category =
	STAT_CATEGORY("memory_pressure",
	              memory_pressure_runs,
	              memory_pressure_fields);

static const struct stat_field numa_migration_fields[] = {
	STAT_FIELD(numa_migration, runs),
	STAT_FIELD(numa_migration, calls),
	STAT_FIELD(numa_migration, failed),
	STAT_FIELD(numa_migration, no_numa),
	STAT_FIELD(numa_migration, sysfs_unreadable),
};

const struct stat_category numa_migration_category =
	STAT_CATEGORY("numa_migration",
	              numa_migration_runs,
	              numa_migration_fields);

static const struct stat_field genetlink_fuzzer_fields[] = {
	STAT_FIELD(genetlink, families_discovered),
	STAT_FIELD(genetlink, discovery_cycles),
	STAT_FIELD(genetlink, msgs_sent),
	STAT_FIELD(genetlink, eperm),
	STAT_FIELD(genetlink, stale_seq_drops),
	STAT_FIELD(genetlink, missing_producer),
	STAT_FIELD(genetlink, discovery_io_err),
	STAT_FIELD(genetlink, discovery_nlerr),
	STAT_FIELD(genetlink, userns_run_fail),
	STAT_FIELD(genetlink, in_ns_open_fail),
	STAT_FIELD(genetlink, send_drain_fail),
};

const struct stat_category genetlink_fuzzer_category =
	STAT_CATEGORY("genetlink_fuzzer",
	              genetlink_families_discovered,
	              genetlink_fuzzer_fields);

static const struct stat_field genl_family_calls_fields[] = {
	STAT_FIELD(genl_family_calls, devlink),
	STAT_FIELD(genl_family_calls, nl80211),
	STAT_FIELD(genl_family_calls, taskstats),
	STAT_FIELD(genl_family_calls, ethtool),
	STAT_FIELD(genl_family_calls, mptcp_pm),
	STAT_FIELD(genl_family_calls, tipc),
	STAT_FIELD(genl_family_calls, wireguard),
	STAT_FIELD(genl_family_calls, l2tp),
	STAT_FIELD(genl_family_calls, gtp),
	STAT_FIELD(genl_family_calls, macsec),
	STAT_FIELD(genl_family_calls, netlabel),
	STAT_FIELD(genl_family_calls, team),
	STAT_FIELD(genl_family_calls, hsr),
	STAT_FIELD(genl_family_calls, fou),
	STAT_FIELD(genl_family_calls, psample),
	STAT_FIELD(genl_family_calls, ila),
	STAT_FIELD(genl_family_calls, ioam6),
	STAT_FIELD(genl_family_calls, seg6),
	STAT_FIELD(genl_family_calls, thermal),
	STAT_FIELD(genl_family_calls, ipvs),
};

const struct stat_category genl_family_calls_category =
	STAT_CATEGORY("genl_family_calls",
	              genl_family_calls_devlink,
	              genl_family_calls_fields);

static const struct stat_field nfnl_subsys_calls_fields[] = {
	STAT_FIELD(nfnl_subsys_calls, ctnetlink),
	STAT_FIELD(nfnl_subsys_calls, ctnetlink_exp),
	STAT_FIELD(nfnl_subsys_calls, nftables),
	STAT_FIELD(nfnl_subsys_calls, ipset),
};

const struct stat_category nfnl_subsys_calls_category =
	STAT_CATEGORY("nfnl_subsys_calls",
	              nfnl_subsys_calls_ctnetlink,
	              nfnl_subsys_calls_fields);

static const struct stat_field netlink_generator_fields[] = {
	STAT_FIELD(netlink, nested_attrs_emitted),
};

const struct stat_category netlink_generator_category =
	STAT_CATEGORY("netlink_generator",
	              netlink_nested_attrs_emitted,
	              netlink_generator_fields);

static const struct stat_field tracefs_fuzzer_fields[] = {
	STAT_FIELD_JSON(tracefs_kprobe_writes, open_fail,        "kprobe_open_fail"),
	STAT_FIELD_JSON(tracefs_kprobe_writes, write_fail,       "kprobe_write_fail"),
	STAT_FIELD_JSON(tracefs_kprobe_writes, write_ok,         "kprobe_write_ok"),
	STAT_FIELD_JSON(tracefs_uprobe_writes, open_fail,        "uprobe_open_fail"),
	STAT_FIELD_JSON(tracefs_uprobe_writes, write_fail,       "uprobe_write_fail"),
	STAT_FIELD_JSON(tracefs_uprobe_writes, write_ok,         "uprobe_write_ok"),
	STAT_FIELD_JSON(tracefs_filter_writes, open_fail,        "filter_open_fail"),
	STAT_FIELD_JSON(tracefs_filter_writes, write_fail,       "filter_write_fail"),
	STAT_FIELD_JSON(tracefs_filter_writes, write_ok,         "filter_write_ok"),
	STAT_FIELD_JSON(tracefs_event_enable_writes, open_fail,  "event_enable_open_fail"),
	STAT_FIELD_JSON(tracefs_event_enable_writes, write_fail, "event_enable_write_fail"),
	STAT_FIELD_JSON(tracefs_event_enable_writes, write_ok,   "event_enable_write_ok"),
	STAT_FIELD_JSON(tracefs_misc_writes, open_fail,          "misc_open_fail"),
	STAT_FIELD_JSON(tracefs_misc_writes, write_fail,         "misc_write_fail"),
	STAT_FIELD_JSON(tracefs_misc_writes, write_ok,           "misc_write_ok"),
};

const struct stat_category tracefs_fuzzer_category =
	STAT_CATEGORY("tracefs_fuzzer",
	              tracefs_kprobe_writes_open_fail,
	              tracefs_fuzzer_fields);

static const struct stat_field bpf_fd_provider_fields[] = {
	STAT_FIELD(bpf, maps_provided),
	STAT_FIELD(bpf, progs_provided),
};

const struct stat_category bpf_fd_provider_category =
	STAT_CATEGORY("bpf_fd_provider",
	              bpf_maps_provided,
	              bpf_fd_provider_fields);

void dump_stats_json_basic_subsystems(void)
{
	stat_category_emit_json(&vfs_writes_category);
	putchar(',');
	stat_category_emit_json(&memory_pressure_category);
	putchar(',');
	stat_category_emit_json(&numa_migration_category);
	putchar(',');
	stat_category_emit_json(&genetlink_fuzzer_category);
	putchar(',');
	stat_category_emit_json(&genl_family_calls_category);
	putchar(',');
	stat_category_emit_json(&nfnl_subsys_calls_category);
	putchar(',');
	stat_category_emit_json(&netlink_generator_category);
	putchar(',');
	stat_category_emit_json(&tracefs_fuzzer_category);
	putchar(',');
	stat_category_emit_json(&bpf_fd_provider_category);
	putchar(',');
}

void dump_stats_json_iouring_and_zombies(void)
{
	stat_category_emit_json(&recipe_runner_category);
	putchar(',');
	stat_category_emit_json(&iouring_recipes_category);
	putchar(',');
	stat_category_emit_json(&iouring_eventfd_category);
	putchar(',');
	stat_category_emit_json(&aio_category);
	putchar(',');
	stat_category_emit_json(&errno_gradient_category);
	putchar(',');
	stat_category_emit_json(&cold_overflow_category);
	putchar(',');
	stat_category_emit_json(&inplace_crypto_category);
	putchar(',');
	stat_category_emit_json(&fd_runtime_skipped_category);
	putchar(',');
	stat_category_emit_json(&child_category);
	putchar(',');
	stat_category_emit_json(&parent_category);
	putchar(',');
	stat_category_emit_json(&uid_change_category);
	putchar(',');
	stat_category_emit_json(&no_domains_category);
	putchar(',');
	stat_category_emit_json(&zombie_slots_category);
	putchar(',');
}

void dump_stats_json_corruption_and_audit(void)
{
	printf("\"corruption\":{\"fd_event_ring_noncanon\":%lu,"
			"\"fd_event_ring_canary\":%lu,\"fd_event_payload\":%lu,"
			"\"stats_ring_noncanon\":%lu,\"stats_ring_canary\":%lu,"
			"\"deferred_free_corrupt_ptr\":%lu,"
			"\"post_handler_corrupt_ptr\":%lu,\"deferred_free_reject\":%lu,"
			"\"deferred_free_reject_pathname\":%lu,"
			"\"deferred_free_reject_iovec\":%lu,"
			"\"deferred_free_reject_sockaddr\":%lu,"
			"\"deferred_free_reject_other\":%lu,"
			"\"snapshot_non_heap_reject\":%lu,"
			"\"rec_canary_stomped\":%lu,\"rzs_blanket_reject\":%lu,"
			"\"retfd_blanket_reject\":%lu,"
			"\"arena_ptr_stale_caught_arg\":%lu,"
			"\"arena_ptr_stale_caught_post_state\":%lu,"
			"\"sibling_mprotect_failed\":%lu,"
			"\"destroy_object_idx\":%lu,"
			"\"global_obj_uaf_caught\":%lu,"
			"\"maps_pool_draw_exhausted\":%lu,"
			"\"maps_reject_pool_empty\":%lu,"
			"\"maps_reject_bogus_obj_ptr\":%lu,"
			"\"maps_reject_alloc_track_miss\":%lu,"
			"\"maps_reject_alloc_track_miss_anon\":%lu,"
			"\"maps_reject_alloc_track_miss_file\":%lu,"
			"\"maps_reject_alloc_track_miss_testfile\":%lu,"
			"\"maps_reject_size_zero\":%lu,"
			"\"maps_reject_size_too_large\":%lu,"
			"\"maps_pool_chosen_anon\":%lu,"
			"\"maps_pool_chosen_file\":%lu,"
			"\"maps_pool_chosen_testfile\":%lu,"
			"\"maps_reject_pool_empty_anon\":%lu,"
			"\"maps_reject_pool_empty_file\":%lu,"
			"\"maps_reject_pool_empty_testfile\":%lu,"
			"\"maps_prot_reject_by_mask\":[%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu],"
			"\"maps_pick_attempts_sum\":%lu,"
			"\"maps_pick_successes\":%lu,"
			"\"maps_pick_with_prot_attempts_sum\":%lu,"
			"\"maps_pick_with_prot_successes\":%lu,"
			"\"maps_type_resolution_calls\":%lu,"
			"\"maps_type_resolution_scan_length_sum\":%lu,"
			"\"maps_type_resolution_hits\":%lu,"
			"\"chain_corpus_save_dup_shape\":%lu,"
			"\"chain_corpus_save_unique_shape\":%lu,"
			"\"deferred_free_reject_misaligned\":%lu,"
			"\"deferred_free_reject_corrupt_shape\":%lu,"
			"\"deferred_free_reject_non_heap\":%lu,"
			"\"deferred_free_reject_untracked\":%lu,"
			"\"nested_scrub_reject_untracked\":%lu,"
			"\"deferred_free_reject_shared_region\":%lu,"
			"\"deferred_free_outstanding_vmas\":%lu,"
			"\"deferred_free_vma_fallback_immediate\":%lu,"
			"\"deferred_free_enomem_drain\":%lu,"
			"\"deferred_free_rw_restore_enomem\":%lu,"
			"\"deferred_free_pre_dispatch_leaked\":%lu,"
			"\"ring_evict_leaked\":%lu,"
			"\"deferred_free_ring_owned_skip\":%lu,"
			"\"deferred_free_double_admit_skip\":%lu,"
			"\"alloc_track_refresh_ring_owned_skip\":%lu,"
			"\"alloc_track_refresh_unverified_skip\":%lu,"
			"\"alloc_track_refresh_consume_miss\":%lu,"
			"\"pagecache_canary_corrupt_caught\":%lu,"
			"\"objpool_array_stale_caught\":%lu,"
			"\"lock_word_scribbled\":%lu,"
			"\"lock_held_scribble\":%lu,"
			"\"chain_replay_len_corrupt\":%lu},"
		"\"shared_buffer\":{\"args_redirected\":%lu,\"range_overlaps_shared_rejects\":%lu,"
			"\"libc_heap_redirected\":%lu,\"libc_heap_embedded_redirected\":%lu,"
			"\"mm_gate_post_slip\":%lu},",
		shm->stats.fd.event_ring_corrupted,
		shm->stats.fd.event_ring_overwritten,
		shm->stats.fd.event_payload_corrupt,
		shm->stats.stats_ring_corrupted,
		shm->stats.stats_ring_overwritten,
		parent_stats.deferred_free_corrupt_ptr,
		parent_stats.post_handler_corrupt_ptr,
		parent_stats.deferred_free_reject,
		parent_stats.deferred_free_reject_pathname,
		parent_stats.deferred_free_reject_iovec,
		parent_stats.deferred_free_reject_sockaddr,
		parent_stats.deferred_free_reject_other,
		parent_stats.snapshot_non_heap_reject,
		shm->stats.rec_canary_stomped,
		shm->stats.rzs_blanket_reject,
		shm->stats.retfd_blanket_reject,
		shm->stats.arena_ptr_stale_caught_arg,
		shm->stats.arena_ptr_stale_caught_post_state,
		shm->stats.sibling_mprotect_failed,
		shm->stats.destroy_object_idx_corrupt,
		shm->stats.global_obj_uaf_caught,
		shm->stats.maps.pool_draw_exhausted,
		shm->stats.maps.reject_pool_empty,
		shm->stats.maps.reject_bogus_obj_ptr,
		shm->stats.maps.reject_alloc_track_miss,
		shm->stats.maps.reject_alloc_track_miss_anon,
		shm->stats.maps.reject_alloc_track_miss_file,
		shm->stats.maps.reject_alloc_track_miss_testfile,
		shm->stats.maps.reject_size_zero,
		shm->stats.maps.reject_size_too_large,
		shm->stats.maps.pool_chosen_anon,
		shm->stats.maps.pool_chosen_file,
		shm->stats.maps.pool_chosen_testfile,
		shm->stats.maps.reject_pool_empty_anon,
		shm->stats.maps.reject_pool_empty_file,
		shm->stats.maps.reject_pool_empty_testfile,
		shm->stats.maps.prot_reject_by_mask[0],
		shm->stats.maps.prot_reject_by_mask[1],
		shm->stats.maps.prot_reject_by_mask[2],
		shm->stats.maps.prot_reject_by_mask[3],
		shm->stats.maps.prot_reject_by_mask[4],
		shm->stats.maps.prot_reject_by_mask[5],
		shm->stats.maps.prot_reject_by_mask[6],
		shm->stats.maps.prot_reject_by_mask[7],
		shm->stats.maps.pick_attempts_sum,
		shm->stats.maps.pick_successes,
		shm->stats.maps.pick_with_prot_attempts_sum,
		shm->stats.maps.pick_with_prot_successes,
		shm->stats.maps.type_resolution_calls,
		shm->stats.maps.type_resolution_scan_length_sum,
		shm->stats.maps.type_resolution_hits,
		shm->stats.chain_corpus_save_dup_shape,
		shm->stats.chain_corpus_save_unique_shape,
		shm->stats.deferred_free_reject_misaligned,
		shm->stats.deferred_free_reject_corrupt_shape,
		shm->stats.deferred_free_reject_non_heap,
		shm->stats.deferred_free_reject_untracked,
		shm->stats.nested_scrub_reject_untracked,
		shm->stats.deferred_free_reject_shared_region,
		shm->stats.deferred_free_outstanding_vmas,
		shm->stats.deferred_free_vma_fallback_immediate,
		shm->stats.deferred_free_enomem_drain,
		shm->stats.deferred_free_rw_restore_enomem,
		shm->stats.deferred_free_pre_dispatch_leaked,
		shm->stats.ring_evict_leaked,
		shm->stats.deferred_free_ring_owned_skip,
		shm->stats.deferred_free_double_admit_skip,
		shm->stats.alloc_track_refresh_ring_owned_skip,
		shm->stats.alloc_track_refresh_unverified_skip,
		shm->stats.alloc_track_refresh_consume_miss,
		shm->stats.pagecache_canary_corrupt_caught,
		shm->stats.objpool_array_stale_caught,
		parent_stats.lock_word_scribbled,
		shm->stats.lock_held_scribble,
		shm->stats.chain_replay_len_corrupt,
		parent_stats.shared_buffer_redirected, parent_stats.range_overlaps_shared_rejects,
		parent_stats.libc_heap_redirected, parent_stats.libc_heap_embedded_redirected,
		parent_stats.mm_gate_post_slip);
}

void dump_stats_json_lifecycle_and_storms(void)
{
	stat_category_emit_json(&fs_lifecycle_category);
	putchar(',');
	stat_category_emit_json(&futex_storm_category);
	putchar(',');
	stat_category_emit_json(&futex_pi_requeue_rollback_category);
	putchar(',');
}
