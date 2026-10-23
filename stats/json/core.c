/*
 * Core (non-network) JSON section emitters for --stats-json.
 * Covers fault-injection, fd-lifecycle, oracle, basic
 * subsystems (vfs / memory-pressure / numa / netlink families /
 * tracefs / bpf), iouring / zombie, corruption / audit, and
 * fs-lifecycle / futex-storm.  The basic-subsystem, fault-injection,
 * corruption and shared-buffer descriptor tables live here rather
 * than under stats/categories/ because they are still JSON-only
 * consumers.
 */

#include <stdio.h>
#include "shm.h"
#include "stats-internal.h"
#include "stats/json/internal.h"
#include "stats_ring.h"

/*
 * Rows that read parent_stats or emit an array are spelled out: the
 * STAT_FIELD* macros only reach scalars in shm->stats.
 */
static const struct stat_field fault_injection_fields[] = {
	{ .name = "armed_fail_nth", .from_aggregate = true,
	  .offset = offsetof(struct stats_aggregate, fault_injected) },
	{ .name = "returned_enomem", .from_aggregate = true,
	  .offset = offsetof(struct stats_aggregate, fault_consumed) },
};

static const struct stat_category fault_injection_category =
	STAT_CATEGORY("fault_injection",
	              fault_injection_fields);

/*
 * Emit every counter from struct stats_s as a single JSON object.
 * All scalar counters are emitted unconditionally so consumers see a stable
 * schema regardless of which subsystems happened to fire on this run.
 */
void dump_stats_json_fault_and_fd_lifecycle(void)
{
	json_stats_sep();
	stat_category_emit_json(&fault_injection_category);
	json_stats_sep();
	stat_category_emit_json(&fd_lifecycle_category);
}

void dump_stats_json_oracle(void)
{
	json_stats_sep();
	stat_category_emit_json(&oracle_category);
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
 * The JSON walker emits every category unconditionally.  The gate_field
 * argument to STAT_CATEGORY is not stored in the descriptor; text emission
 * via stat_category_emit_text() fires when any field is non-zero, so the
 * gate choices below are effectively documentation only.  Each text-side
 * block in dump_stats_text() stays hand-coded for now and picks its own
 * gate predicate.
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
	              vfs_writes_fields);

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
	              genl_family_calls_fields);

static const struct stat_field nfnl_subsys_calls_fields[] = {
	STAT_FIELD(nfnl_subsys_calls, ctnetlink),
	STAT_FIELD(nfnl_subsys_calls, ctnetlink_exp),
	STAT_FIELD(nfnl_subsys_calls, nftables),
	STAT_FIELD(nfnl_subsys_calls, ipset),
};

const struct stat_category nfnl_subsys_calls_category =
	STAT_CATEGORY("nfnl_subsys_calls",
	              nfnl_subsys_calls_fields);

static const struct stat_field netlink_generator_fields[] = {
	STAT_FIELD(netlink, nested_attrs_emitted),
	STAT_FIELD(netlink, nested_attrs_accepted),
	STAT_FIELD(netlink, nested_attr_skipped_width),
	STAT_FIELD(netlink, nested_attr_built_width),
	STAT_FIELD(netlink, nested_attr_build_calls),
	STAT_FIELD(netlink, nested_attr_lost_align),
	STAT_FIELD(netlink, stab_emit_skipped),
};

const struct stat_category netlink_generator_category =
	STAT_CATEGORY("netlink_generator",
	              netlink_generator_fields);

static const struct stat_field rtnl_ack_oracle_fields[] = {
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, accepted,   "accepted"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, einval,     "einval"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, erange,     "erange"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, eopnotsupp, "eopnotsupp"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, eperm,      "eperm"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, other,      "other"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, send_fail,          "send_fail"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, no_reply_exhausted, "no_reply_exhausted"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, no_reply_clean,     "no_reply_clean"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, stale_done,         "stale_done"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, stale_other,        "stale_other"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, stale_foreign_ack,  "stale_foreign_ack"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, stale_undersized,   "stale_undersized"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, stale_truncated,    "stale_truncated"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, stale_unparsed,     "stale_unparsed"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, bad_framing,        "bad_framing"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, dump_skipped,       "dump_skipped"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, recv_enobufs,       "recv_enobufs"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, recv_eintr,         "recv_eintr"),
	STAT_FIELD_JSON_SUB(rtnl_ack_oracle, recv_error,         "recv_error"),
};

const struct stat_category rtnl_ack_oracle_category =
	STAT_CATEGORY("rtnl_ack_oracle",
	              rtnl_ack_oracle_fields);

static const struct stat_field bpf_fd_provider_fields[] = {
	STAT_FIELD_SUB(ebpf_gen, maps_provided),
	STAT_FIELD_SUB(ebpf_gen, progs_provided),
	STAT_FIELD_SUB(ebpf_gen, bpf_prog_load_rejected),
	STAT_FIELD_SUB(ebpf_gen, bpf_prog_load_einval),
};

const struct stat_category bpf_fd_provider_category =
	STAT_CATEGORY("bpf_fd_provider",
	              bpf_fd_provider_fields);

/*
 * frseq (frequency-sequence) damper counters live two levels deep
 * inside frontier.discriminator; spell out the offsetof path because
 * STAT_FIELD_SUB only handles a single sub.field level.
 */
static const struct stat_field frontier_discriminator_fields[] = {
	{ .name = "frseq_candidates",
	  .offset = offsetof(struct stats_s,
	                     frontier.discriminator.frseq_candidates) },
	{ .name = "frseq_would_skip",
	  .offset = offsetof(struct stats_s,
	                     frontier.discriminator.frseq_would_skip) },
};

static const struct stat_category frontier_discriminator_category =
	STAT_CATEGORY("frontier_discriminator",
	              frontier_discriminator_fields);

static const struct stat_field childop_burst_fields[] = {
	STAT_FIELD_SUB(childop, burst_alt_picks_window),
};

static const struct stat_category childop_burst_category =
	STAT_CATEGORY("childop_burst",
	              childop_burst_fields);

static const struct stat_field corrupt_ptr_probe_fields[] = {
	STAT_FIELD_SUB(corrupt_ptr, sample_seq),
};

static const struct stat_category corrupt_ptr_probe_category =
	STAT_CATEGORY("corrupt_ptr_probe",
	              corrupt_ptr_probe_fields);

void dump_stats_json_basic_subsystems(void)
{
	json_stats_sep();
	stat_category_emit_json(&vfs_writes_category);
	json_stats_sep();
	stat_category_emit_json(&genl_family_calls_category);
	json_stats_sep();
	stat_category_emit_json(&nfnl_subsys_calls_category);
	json_stats_sep();
	stat_category_emit_json(&netlink_generator_category);
	json_stats_sep();
	stat_category_emit_json(&rtnl_ack_oracle_category);
	json_stats_sep();
	stat_category_emit_json(&bpf_fd_provider_category);
	json_stats_sep();
	stat_category_emit_json(&frontier_discriminator_category);
	json_stats_sep();
	stat_category_emit_json(&childop_burst_category);
	json_stats_sep();
	stat_category_emit_json(&corrupt_ptr_probe_category);
}

void dump_stats_json_iouring_and_zombies(void)
{
	json_stats_sep();
	stat_category_emit_json(&aio_category);
	json_stats_sep();
	stat_category_emit_json(&errno_gradient_category);
	json_stats_sep();
	stat_category_emit_json(&cold_overflow_category);
	json_stats_sep();
	stat_category_emit_json(&fd_runtime_skipped_category);
	json_stats_sep();
	stat_category_emit_json(&child_category);
	json_stats_sep();
	stat_category_emit_json(&parent_category);
	json_stats_sep();
	stat_category_emit_json(&uid_change_category);
	json_stats_sep();
	stat_category_emit_json(&no_domains_category);
	json_stats_sep();
	stat_category_emit_json(&zombie_slots_category);
}

/* The parent_stats and array rows are spelled out as in
 * fault_injection_fields[]. */
static const struct stat_field corruption_fields[] = {
	STAT_FIELD_JSON_SUB(fd, event_ring_overwritten, "fd_event_ring_canary"),
	STAT_FIELD_JSON_SUB(fd, event_payload_corrupt, "fd_event_payload"),
	STAT_FIELD_JSON_SUB(diag, stats_ring_overwritten, "stats_ring_canary"),
	{ .name = "deferred_free_corrupt_ptr", .from_aggregate = true,
	  .offset = offsetof(struct stats_aggregate, deferred_free_corrupt_ptr) },
	{ .name = "post_handler_corrupt_ptr", .from_aggregate = true,
	  .offset = offsetof(struct stats_aggregate, post_handler_corrupt_ptr) },
	{ .name = "deferred_free_reject", .from_aggregate = true,
	  .offset = offsetof(struct stats_aggregate, deferred_free_reject) },
	{ .name = "deferred_free_reject_pathname", .from_aggregate = true,
	  .offset = offsetof(struct stats_aggregate, deferred_free_reject_pathname) },
	{ .name = "deferred_free_reject_iovec", .from_aggregate = true,
	  .offset = offsetof(struct stats_aggregate, deferred_free_reject_iovec) },
	{ .name = "deferred_free_reject_sockaddr", .from_aggregate = true,
	  .offset = offsetof(struct stats_aggregate, deferred_free_reject_sockaddr) },
	{ .name = "deferred_free_reject_other", .from_aggregate = true,
	  .offset = offsetof(struct stats_aggregate, deferred_free_reject_other) },
	{ .name = "snapshot_non_heap_reject", .from_aggregate = true,
	  .offset = offsetof(struct stats_aggregate, snapshot_non_heap_reject) },
	STAT_FIELD_SUB(diag, rec_canary_stomped),
	STAT_FIELD_SUB(diag, rzs_blanket_reject),
	STAT_FIELD_SUB(diag, retfd_blanket_reject),
	STAT_FIELD_SUB(diag, arena_ptr_stale_caught_arg),
	STAT_FIELD_SUB(diag, arena_ptr_stale_caught_post_state),
	STAT_FIELD_SUB(diag, read_walk_aborted),
	STAT_FIELD_SUB(diag, write_walk_aborted),
	STAT_FIELD_SUB(diag, sibling_mprotect_failed),
	STAT_FIELD_JSON_SUB(diag, destroy_object_idx_corrupt, "destroy_object_idx"),
	STAT_FIELD_SUB(diag, global_obj_uaf_caught),
	STAT_FIELD_SUB(diag, mseal_content_oracle_fail),
	STAT_FIELD_SUB(diag, mseal_unexpected_success),
	STAT_FIELD_JSON_SUB(maps, pool_draw_exhausted, "maps_pool_draw_exhausted"),
	STAT_FIELD_JSON_SUB(maps, reject_pool_empty, "maps_reject_pool_empty"),
	STAT_FIELD_JSON_SUB(maps, reject_bogus_obj_ptr, "maps_reject_bogus_obj_ptr"),
	STAT_FIELD_JSON_SUB(maps, reject_alloc_track_miss, "maps_reject_alloc_track_miss"),
	STAT_FIELD_JSON_SUB(maps, reject_alloc_track_miss_anon, "maps_reject_alloc_track_miss_anon"),
	STAT_FIELD_JSON_SUB(maps, reject_alloc_track_miss_file, "maps_reject_alloc_track_miss_file"),
	STAT_FIELD_JSON_SUB(maps, reject_alloc_track_miss_testfile, "maps_reject_alloc_track_miss_testfile"),
	STAT_FIELD_JSON_SUB(maps, reject_size_zero, "maps_reject_size_zero"),
	STAT_FIELD_JSON_SUB(maps, reject_size_too_large, "maps_reject_size_too_large"),
	STAT_FIELD_JSON_SUB(maps, pool_chosen_anon, "maps_pool_chosen_anon"),
	STAT_FIELD_JSON_SUB(maps, pool_chosen_file, "maps_pool_chosen_file"),
	STAT_FIELD_JSON_SUB(maps, pool_chosen_testfile, "maps_pool_chosen_testfile"),
	STAT_FIELD_JSON_SUB(maps, reject_pool_empty_anon, "maps_reject_pool_empty_anon"),
	STAT_FIELD_JSON_SUB(maps, reject_pool_empty_file, "maps_reject_pool_empty_file"),
	STAT_FIELD_JSON_SUB(maps, reject_pool_empty_testfile, "maps_reject_pool_empty_testfile"),
	{ .name = "maps_prot_reject_by_mask", .n_elems = 8,
	  .offset = offsetof(struct stats_s, maps.prot_reject_by_mask) },
	STAT_FIELD_JSON_SUB(maps, pick_attempts_sum, "maps_pick_attempts_sum"),
	STAT_FIELD_JSON_SUB(maps, pick_successes, "maps_pick_successes"),
	STAT_FIELD_JSON_SUB(maps, pick_with_prot_attempts_sum, "maps_pick_with_prot_attempts_sum"),
	STAT_FIELD_JSON_SUB(maps, pick_with_prot_successes, "maps_pick_with_prot_successes"),
	STAT_FIELD_JSON_SUB(maps, type_resolution_calls, "maps_type_resolution_calls"),
	STAT_FIELD_JSON_SUB(maps, type_resolution_scan_length_sum, "maps_type_resolution_scan_length_sum"),
	STAT_FIELD_JSON_SUB(maps, type_resolution_hits, "maps_type_resolution_hits"),
	STAT_FIELD_JSON_SUB(chain_corpus, save_dup_shape, "chain_corpus_save_dup_shape"),
	STAT_FIELD_JSON_SUB(chain_corpus, save_unique_shape, "chain_corpus_save_unique_shape"),
	STAT_FIELD_JSON_SUB(deferred_free, reject_misaligned, "deferred_free_reject_misaligned"),
	STAT_FIELD_JSON_SUB(deferred_free, reject_corrupt_shape, "deferred_free_reject_corrupt_shape"),
	STAT_FIELD_JSON_SUB(deferred_free, reject_non_heap, "deferred_free_reject_non_heap"),
	STAT_FIELD_JSON_SUB(deferred_free, reject_untracked, "deferred_free_reject_untracked"),
	STAT_FIELD_SUB(deferred_free, nested_scrub_reject_untracked),
	STAT_FIELD_JSON_SUB(deferred_free, reject_shared_region, "deferred_free_reject_shared_region"),
	STAT_FIELD_JSON_SUB(deferred_free, outstanding_vmas, "deferred_free_outstanding_vmas"),
	STAT_FIELD_JSON_SUB(deferred_free, vma_fallback_immediate, "deferred_free_vma_fallback_immediate"),
	STAT_FIELD_JSON_SUB(deferred_free, enomem_drain, "deferred_free_enomem_drain"),
	STAT_FIELD_JSON_SUB(deferred_free, rw_restore_enomem, "deferred_free_rw_restore_enomem"),
	STAT_FIELD_JSON_SUB(deferred_free, pre_dispatch_leaked, "deferred_free_pre_dispatch_leaked"),
	STAT_FIELD_SUB(deferred_free, ring_evict_leaked),
	STAT_FIELD_JSON_SUB(deferred_free, tracked_free_unverified_leak, "deferred_free_tracked_free_unverified_leak"),
	STAT_FIELD_JSON_SUB(deferred_free, gen_arena_admitted, "deferred_free_gen_arena_admitted"),
	STAT_FIELD_JSON_SUB(deferred_free, gen_arena_retired_ok, "deferred_free_gen_arena_retired_ok"),
	STAT_FIELD_JSON_SUB(deferred_free, gen_arena_retire_reject, "deferred_free_gen_arena_retire_reject"),
	STAT_FIELD_JSON_SUB(deferred_free, gen_arena_pressure_leak, "deferred_free_gen_arena_pressure_leak"),
	STAT_FIELD_JSON_SUB(deferred_free, ring_owned_skip, "deferred_free_ring_owned_skip"),
	STAT_FIELD_JSON_SUB(deferred_free, double_admit_skip, "deferred_free_double_admit_skip"),
	STAT_FIELD_SUB(deferred_free, alloc_track_refresh_ring_owned_skip),
	STAT_FIELD_SUB(deferred_free, alloc_track_refresh_unverified_skip),
	STAT_FIELD_SUB(deferred_free, alloc_track_refresh_consume_miss),
	STAT_FIELD_SUB(deferred_free, alloc_track_lookup_array_fallback_hit),
	STAT_FIELD_SUB(diag, pagecache_canary_corrupt_caught),
	STAT_FIELD_SUB(diag, objpool_array_stale_caught),
	{ .name = "lock_word_scribbled", .from_aggregate = true,
	  .offset = offsetof(struct stats_aggregate, lock_word_scribbled) },
	{ .name = "lossless_slot_implausible", .from_aggregate = true,
	  .offset = offsetof(struct stats_aggregate, lossless_slot_implausible) },
	STAT_FIELD_SUB(diag, lock_held_scribble),
	STAT_FIELD_JSON_SUB(chain_restype, replay_len_corrupt, "chain_replay_len_corrupt"),
};

static const struct stat_category corruption_category =
	STAT_CATEGORY("corruption",
	              corruption_fields);

static const struct stat_field shared_buffer_fields[] = {
	{ .name = "args_redirected", .from_aggregate = true,
	  .offset = offsetof(struct stats_aggregate, shared_buffer_redirected) },
	{ .name = "range_overlaps_shared_rejects", .from_aggregate = true,
	  .offset = offsetof(struct stats_aggregate, range_overlaps_shared_rejects) },
	{ .name = "libc_heap_redirected", .from_aggregate = true,
	  .offset = offsetof(struct stats_aggregate, libc_heap_redirected) },
	{ .name = "libc_heap_embedded_redirected", .from_aggregate = true,
	  .offset = offsetof(struct stats_aggregate, libc_heap_embedded_redirected) },
	{ .name = "mm_gate_post_slip", .from_aggregate = true,
	  .offset = offsetof(struct stats_aggregate, mm_gate_post_slip) },
};

static const struct stat_category shared_buffer_category =
	STAT_CATEGORY("shared_buffer",
	              shared_buffer_fields);

void dump_stats_json_corruption_and_audit(void)
{
	json_stats_sep();
	stat_category_emit_json(&corruption_category);
	json_stats_sep();
	stat_category_emit_json(&shared_buffer_category);
}

void dump_stats_json_lifecycle_and_storms(void)
{
	json_stats_sep();
	stat_category_emit_json(&prctl_futex_hash_category);
}
