
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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
 * Periodic surface of the defense-counter family that dump_stats() only
 * emits at end-of-run.  Called once per main_loop tick from the parent;
 * every DEFENSE_DUMP_INTERVAL_SEC the diff between the current counter
 * value and the value cached at the prior dump is divided by the elapsed
 * window and emitted as a per-second rate, so an operator watching a
 * long fuzz run can see which guards are catching real wild writes vs
 * sitting at noise without waiting for the run to end.  Counters with a
 * zero delta are skipped so the per-window line stays short on a quiet
 * fleet; the whole block is suppressed entirely on a window where every
 * counter held flat.  Listed once in periodic_counter_rates[] so adding a new
 * defense counter only needs one edit to get periodic visibility.
 *
 * DEFENSE_DUMP_INTERVAL_SEC lives in stats-internal.h so the sibling
 * periodic rate dumps (cost_pool, top_syscalls) and the kcov_cmp
 * cluster all share one cadence value.
 */

static const struct {
	const char *name;
	size_t off;
	bool    from_aggregate;	/* true: read from parent_stats; false: shm->stats */
} periodic_counter_rates[] = {
	{ "shared_buffer_redirected",
	  offsetof(struct stats_aggregate, shared_buffer_redirected), true },
	{ "range_overlaps_shared_rejects",
	  offsetof(struct stats_aggregate, range_overlaps_shared_rejects), true },
	{ "libc_heap_redirected",
	  offsetof(struct stats_aggregate, libc_heap_redirected), true },
	{ "libc_heap_embedded_redirected",
	  offsetof(struct stats_aggregate, libc_heap_embedded_redirected), true },
	{ "asb_relocate_readable_skip",
	  offsetof(struct stats_aggregate, asb_relocate_readable_skip), true },
	{ "asb_relocate_copy_fault",
	  offsetof(struct stats_aggregate, asb_relocate_copy_fault), true },
	{ "heap_pointer_outside_cache",
	  offsetof(struct stats_aggregate, heap_pointer_outside_cache), true },
	{ "heap_brk_stale_window_hit",
	  offsetof(struct stats_aggregate, heap_brk_stale_window_hit), true },
	{ "mm_gate_post_slip",
	  offsetof(struct stats_aggregate, mm_gate_post_slip), true },
	{ "post_handler_corrupt_ptr",
	  offsetof(struct stats_aggregate, post_handler_corrupt_ptr), true },
	{ "validator_rejected",
	  offsetof(struct stats_aggregate, validator_rejected), true },
	{ "arg_constraint_repaired",
	  offsetof(struct stats_aggregate, arg_constraint_repaired), true },
	{ "arg_constraint_kept_incoherent",
	  offsetof(struct stats_aggregate, arg_constraint_kept_incoherent), true },
	{ "epoll_wait_null_events_alloc_fail",
	  offsetof(struct stats_s, epoll_wait_null_events_alloc_fail) },
	{ "epoll_wait_null_events_shared_reject",
	  offsetof(struct stats_s, epoll_wait_null_events_shared_reject) },
	{ "deferred_free_reject",
	  offsetof(struct stats_aggregate, deferred_free_reject), true },
	{ "deferred_free_reject_pathname",
	  offsetof(struct stats_aggregate, deferred_free_reject_pathname), true },
	{ "deferred_free_reject_iovec",
	  offsetof(struct stats_aggregate, deferred_free_reject_iovec), true },
	{ "deferred_free_reject_sockaddr",
	  offsetof(struct stats_aggregate, deferred_free_reject_sockaddr), true },
	{ "deferred_free_reject_other",
	  offsetof(struct stats_aggregate, deferred_free_reject_other), true },
	{ "snapshot_non_heap_reject",
	  offsetof(struct stats_aggregate, snapshot_non_heap_reject), true },
	{ "deferred_free_corrupt_ptr",
	  offsetof(struct stats_aggregate, deferred_free_corrupt_ptr), true },
	{ "arg_shadow_stomp",
	  offsetof(struct stats_aggregate, arg_shadow_stomp), true },
	{ "lock_word_scribbled",
	  offsetof(struct stats_aggregate, lock_word_scribbled), true },
	{ "lock_held_scribble",
	  offsetof(struct stats_s, lock_held_scribble) },
	{ "rec_canary_stomped",
	  offsetof(struct stats_s, rec_canary_stomped) },
	{ "rzs_blanket_reject",
	  offsetof(struct stats_s, rzs_blanket_reject) },
	{ "retfd_blanket_reject",
	  offsetof(struct stats_s, retfd_blanket_reject) },
	{ "arena_ptr_stale_caught_arg",
	  offsetof(struct stats_s, arena_ptr_stale_caught_arg) },
	{ "arena_ptr_stale_caught_post_state",
	  offsetof(struct stats_s, arena_ptr_stale_caught_post_state) },
	{ "execve_self_exec_blocked",
	  offsetof(struct stats_s, execve_self_exec_blocked) },
	{ "corpus_count_overcap_caught",
	  offsetof(struct stats_s, corpus_count_overcap_caught) },
	{ "sibling_mprotect_failed",
	  offsetof(struct stats_s, sibling_mprotect_failed) },
	{ "sibling_refreeze_count",
	  offsetof(struct stats_s, sibling_refreeze_count) },
	/* divergence-sentinel anomaly counter, sharded by enum
	 * sentinel_field.  One row per active field id so the periodic
	 * rate dump shows which monitored field is drifting rather than
	 * a lumped headline number.  Gaps in the enum (5..9) are simply
	 * not listed here — their array slots stay zero.
	 */
	{ "divergence_sentinel_anomalies_sysname",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_UNAME_SYSNAME]) },
	{ "divergence_sentinel_anomalies_release",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_UNAME_RELEASE]) },
	{ "divergence_sentinel_anomalies_version",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_UNAME_VERSION]) },
	{ "divergence_sentinel_anomalies_machine",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_UNAME_MACHINE]) },
	{ "divergence_sentinel_anomalies_totalram",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_SYSINFO_TOTALRAM]) },
	{ "divergence_sentinel_anomalies_totalswap",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_SYSINFO_TOTALSWAP]) },
	{ "divergence_sentinel_anomalies_totalhigh",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_SYSINFO_TOTALHIGH]) },
	{ "divergence_sentinel_anomalies_mem_unit",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_SYSINFO_MEM_UNIT]) },
	/* SF_UNAME_RELEASE / SF_UNAME_MACHINE bumps land here instead of
	 * on the per-field anomaly shards above — personality()-driven
	 * legitimate drift, kept separate so the corruption histogram
	 * stays a real signal. */
	{ "divergence_sentinel_expected_drift",
	  offsetof(struct stats_s, divergence_sentinel_expected_drift) },
	{ "iouring_enter_mask_corrupt",
	  offsetof(struct stats_s, iouring_enter_mask_corrupt) },
	{ "watchdog_sigalrm_clobbered",
	  offsetof(struct stats_s, watchdog_sigalrm_clobbered) },
	{ "watchdog_sigxcpu_clobbered",
	  offsetof(struct stats_s, watchdog_sigxcpu_clobbered) },
	{ "watchdog_sigalrm_reinstalled",
	  offsetof(struct stats_s, watchdog_sigalrm_reinstalled) },
	{ "watchdog_sigxcpu_reinstalled",
	  offsetof(struct stats_s, watchdog_sigxcpu_reinstalled) },
	{ "fd_event_ring_corrupted",
	  offsetof(struct stats_s, fd.event_ring_corrupted) },
	{ "fd_event_ring_overwritten",
	  offsetof(struct stats_s, fd.event_ring_overwritten) },
	{ "stats_ring_corrupted",
	  offsetof(struct stats_s, stats_ring_corrupted) },
	{ "stats_ring_overwritten",
	  offsetof(struct stats_s, stats_ring_overwritten) },
	{ "fd_event_payload_corrupt",
	  offsetof(struct stats_s, fd.event_payload_corrupt) },
	{ "destroy_object_idx_corrupt",
	  offsetof(struct stats_s, destroy_object_idx_corrupt) },
	{ "global_obj_uaf_caught",
	  offsetof(struct stats_s, global_obj_uaf_caught) },
	{ "maps_pool_draw_exhausted",
	  offsetof(struct stats_s, maps.pool_draw_exhausted) },
	{ "maps_reject_pool_empty",
	  offsetof(struct stats_s, maps.reject_pool_empty) },
	{ "maps_reject_bogus_obj_ptr",
	  offsetof(struct stats_s, maps.reject_bogus_obj_ptr) },
	{ "maps_reject_alloc_track_miss",
	  offsetof(struct stats_s, maps.reject_alloc_track_miss) },
	{ "maps_reject_alloc_track_miss_anon",
	  offsetof(struct stats_s, maps.reject_alloc_track_miss_anon) },
	{ "maps_reject_alloc_track_miss_file",
	  offsetof(struct stats_s, maps.reject_alloc_track_miss_file) },
	{ "maps_reject_alloc_track_miss_testfile",
	  offsetof(struct stats_s, maps.reject_alloc_track_miss_testfile) },
	{ "maps_reject_size_zero",
	  offsetof(struct stats_s, maps.reject_size_zero) },
	{ "maps_reject_size_too_large",
	  offsetof(struct stats_s, maps.reject_size_too_large) },
	/* Map selection / pick-cost rows.  Per-second
	 * rates here let the periodic dump answer "is the
	 * 1000-iter retry budget actually contended" and "which
	 * pool / prot-mask is paying the rejection cost", the
	 * questions the side-index TIER-2/3 rows are gated on. */
	{ "maps_pool_chosen_anon",
	  offsetof(struct stats_s, maps.pool_chosen_anon) },
	{ "maps_pool_chosen_file",
	  offsetof(struct stats_s, maps.pool_chosen_file) },
	{ "maps_pool_chosen_testfile",
	  offsetof(struct stats_s, maps.pool_chosen_testfile) },
	{ "maps_reject_pool_empty_anon",
	  offsetof(struct stats_s, maps.reject_pool_empty_anon) },
	{ "maps_reject_pool_empty_file",
	  offsetof(struct stats_s, maps.reject_pool_empty_file) },
	{ "maps_reject_pool_empty_testfile",
	  offsetof(struct stats_s, maps.reject_pool_empty_testfile) },
	{ "maps_prot_reject_mask_0",
	  offsetof(struct stats_s, maps.prot_reject_by_mask[0]) },
	{ "maps_prot_reject_mask_R",
	  offsetof(struct stats_s, maps.prot_reject_by_mask[1]) },
	{ "maps_prot_reject_mask_W",
	  offsetof(struct stats_s, maps.prot_reject_by_mask[2]) },
	{ "maps_prot_reject_mask_RW",
	  offsetof(struct stats_s, maps.prot_reject_by_mask[3]) },
	{ "maps_prot_reject_mask_X",
	  offsetof(struct stats_s, maps.prot_reject_by_mask[4]) },
	{ "maps_prot_reject_mask_RX",
	  offsetof(struct stats_s, maps.prot_reject_by_mask[5]) },
	{ "maps_prot_reject_mask_WX",
	  offsetof(struct stats_s, maps.prot_reject_by_mask[6]) },
	{ "maps_prot_reject_mask_RWX",
	  offsetof(struct stats_s, maps.prot_reject_by_mask[7]) },
	{ "maps_pick_attempts_sum",
	  offsetof(struct stats_s, maps.pick_attempts_sum) },
	{ "maps_pick_successes",
	  offsetof(struct stats_s, maps.pick_successes) },
	{ "maps_pick_with_prot_attempts_sum",
	  offsetof(struct stats_s, maps.pick_with_prot_attempts_sum) },
	{ "maps_pick_with_prot_successes",
	  offsetof(struct stats_s, maps.pick_with_prot_successes) },
	/* SAMPLED get_map_handle() reject-loop cost.  cycles_sum
	 * accumulates the total rdtsc delta across the loop body on
	 * gated 1/N calls; cycles_count is the sample denominator.
	 * See include/stats.h and mm/maps.c for the sampling gate. */
	{ "maps_pick_cycles_sampled_sum",
	  offsetof(struct stats_s, maps.pick_cycles_sampled_sum) },
	{ "maps_pick_cycles_sampled_count",
	  offsetof(struct stats_s, maps.pick_cycles_sampled_count) },
	/* Log2 histogram of the get_map_handle() retry-loop exit
	 * index, bumped on both success and exhaustion paths.  Mirrors
	 * fd_live_remove_scan_histogram bucket layout: hist_0 is
	 * first-iteration hits, hist_ge64 is the saturating tail. */
	{ "maps_pick_scan_hist_0",
	  offsetof(struct stats_s, maps.pick_scan_histogram[0]) },
	{ "maps_pick_scan_hist_1",
	  offsetof(struct stats_s, maps.pick_scan_histogram[1]) },
	{ "maps_pick_scan_hist_2_3",
	  offsetof(struct stats_s, maps.pick_scan_histogram[2]) },
	{ "maps_pick_scan_hist_4_7",
	  offsetof(struct stats_s, maps.pick_scan_histogram[3]) },
	{ "maps_pick_scan_hist_8_15",
	  offsetof(struct stats_s, maps.pick_scan_histogram[4]) },
	{ "maps_pick_scan_hist_16_31",
	  offsetof(struct stats_s, maps.pick_scan_histogram[5]) },
	{ "maps_pick_scan_hist_32_63",
	  offsetof(struct stats_s, maps.pick_scan_histogram[6]) },
	{ "maps_pick_scan_hist_ge64",
	  offsetof(struct stats_s, maps.pick_scan_histogram[7]) },
	{ "maps_type_resolution_calls",
	  offsetof(struct stats_s, maps.type_resolution_calls) },
	{ "maps_type_resolution_scan_length_sum",
	  offsetof(struct stats_s, maps.type_resolution_scan_length_sum) },
	{ "maps_type_resolution_hits",
	  offsetof(struct stats_s, maps.type_resolution_hits) },
	/* FD bookkeeping rows.  fd_live_remove
	 * histogram surfaces whether the linear scan
	 * an fd live-list index would replace is actually expensive;
	 * fd_event_full_* says which producer drove a ring
	 * overflow; close_range_* surfaces the compression ratio
	 * the range opcode buys vs the per-fd path. */
	{ "fd_live_remove_calls",
	  offsetof(struct stats_s, fd.live_remove_calls) },
	{ "fd_live_remove_miss",
	  offsetof(struct stats_s, fd.live_remove_miss) },
	{ "fd_live_remove_scan_hist_0",
	  offsetof(struct stats_s, fd.live_remove_scan_histogram[0]) },
	{ "fd_live_remove_scan_hist_1",
	  offsetof(struct stats_s, fd.live_remove_scan_histogram[1]) },
	{ "fd_live_remove_scan_hist_2_3",
	  offsetof(struct stats_s, fd.live_remove_scan_histogram[2]) },
	{ "fd_live_remove_scan_hist_4_7",
	  offsetof(struct stats_s, fd.live_remove_scan_histogram[3]) },
	{ "fd_live_remove_scan_hist_8_15",
	  offsetof(struct stats_s, fd.live_remove_scan_histogram[4]) },
	{ "fd_live_remove_scan_hist_16_31",
	  offsetof(struct stats_s, fd.live_remove_scan_histogram[5]) },
	{ "fd_live_remove_scan_hist_32_63",
	  offsetof(struct stats_s, fd.live_remove_scan_histogram[6]) },
	{ "fd_live_remove_scan_hist_ge64",
	  offsetof(struct stats_s, fd.live_remove_scan_histogram[7]) },
	{ "fd_event_full_close",
	  offsetof(struct stats_s, fd.event_full_close) },
	{ "fd_event_full_evict",
	  offsetof(struct stats_s, fd.event_full_evict) },
	{ "fd_event_full_close_range",
	  offsetof(struct stats_s, fd.event_full_close_range) },
	{ "fd_event_close_range_enqueued",
	  offsetof(struct stats_s, fd.event_close_range_enqueued) },
	{ "fd_event_close_range_length_sum",
	  offsetof(struct stats_s, fd.event_close_range_length_sum) },
	/* Chain-corpus duplicate-shape rate.  Dup
	 * vs unique count over the K=8 most-recent slots; rate
	 * dup/(dup+unique) gates a per-shape chain quota. */
	{ "chain_corpus_save_dup_shape",
	  offsetof(struct stats_s, chain_corpus_save_dup_shape) },
	{ "chain_corpus_save_unique_shape",
	  offsetof(struct stats_s, chain_corpus_save_unique_shape) },
	/* Per-resource-kind chain-generation telemetry
	 * (--chain-resource-typing).  One row per (kind, counter);
	 * per-kind naming so the JSON emitter and check-stats-reachable
	 * audit both see distinct symbols and rate-of-change
	 * dashboards can plot each resource family independently.
	 * Kind ordering MUST match enum chain_resource_kind in
	 * include/sequence.h. */
	{ "chain_restype_produced_epoll_fd",
	  offsetof(struct stats_s, chain_restype_produced[CHAIN_RESTYPE_EPOLL_FD]) },
	{ "chain_restype_produced_timerfd",
	  offsetof(struct stats_s, chain_restype_produced[CHAIN_RESTYPE_TIMERFD]) },
	{ "chain_restype_produced_eventfd",
	  offsetof(struct stats_s, chain_restype_produced[CHAIN_RESTYPE_EVENTFD]) },
	{ "chain_restype_produced_io_uring_fd",
	  offsetof(struct stats_s, chain_restype_produced[CHAIN_RESTYPE_IO_URING_FD]) },
	{ "chain_restype_produced_pidfd",
	  offsetof(struct stats_s, chain_restype_produced[CHAIN_RESTYPE_PIDFD]) },
	{ "chain_restype_produced_socket_tcp",
	  offsetof(struct stats_s, chain_restype_produced[CHAIN_RESTYPE_SOCKET_TCP]) },
	{ "chain_restype_produced_bpf_map_fd",
	  offsetof(struct stats_s, chain_restype_produced[CHAIN_RESTYPE_BPF_MAP_FD]) },
	{ "chain_restype_would_bias_epoll_fd",
	  offsetof(struct stats_s, chain_restype_would_bias[CHAIN_RESTYPE_EPOLL_FD]) },
	{ "chain_restype_would_bias_timerfd",
	  offsetof(struct stats_s, chain_restype_would_bias[CHAIN_RESTYPE_TIMERFD]) },
	{ "chain_restype_would_bias_eventfd",
	  offsetof(struct stats_s, chain_restype_would_bias[CHAIN_RESTYPE_EVENTFD]) },
	{ "chain_restype_would_bias_io_uring_fd",
	  offsetof(struct stats_s, chain_restype_would_bias[CHAIN_RESTYPE_IO_URING_FD]) },
	{ "chain_restype_would_bias_pidfd",
	  offsetof(struct stats_s, chain_restype_would_bias[CHAIN_RESTYPE_PIDFD]) },
	{ "chain_restype_would_bias_socket_tcp",
	  offsetof(struct stats_s, chain_restype_would_bias[CHAIN_RESTYPE_SOCKET_TCP]) },
	{ "chain_restype_would_bias_bpf_map_fd",
	  offsetof(struct stats_s, chain_restype_would_bias[CHAIN_RESTYPE_BPF_MAP_FD]) },
	{ "chain_restype_biased_epoll_fd",
	  offsetof(struct stats_s, chain_restype_biased[CHAIN_RESTYPE_EPOLL_FD]) },
	{ "chain_restype_biased_timerfd",
	  offsetof(struct stats_s, chain_restype_biased[CHAIN_RESTYPE_TIMERFD]) },
	{ "chain_restype_biased_eventfd",
	  offsetof(struct stats_s, chain_restype_biased[CHAIN_RESTYPE_EVENTFD]) },
	{ "chain_restype_biased_io_uring_fd",
	  offsetof(struct stats_s, chain_restype_biased[CHAIN_RESTYPE_IO_URING_FD]) },
	{ "chain_restype_biased_pidfd",
	  offsetof(struct stats_s, chain_restype_biased[CHAIN_RESTYPE_PIDFD]) },
	{ "chain_restype_biased_socket_tcp",
	  offsetof(struct stats_s, chain_restype_biased[CHAIN_RESTYPE_SOCKET_TCP]) },
	{ "chain_restype_biased_bpf_map_fd",
	  offsetof(struct stats_s, chain_restype_biased[CHAIN_RESTYPE_BPF_MAP_FD]) },
	{ "chain_restype_save_epoll_fd",
	  offsetof(struct stats_s, chain_restype_save[CHAIN_RESTYPE_EPOLL_FD]) },
	{ "chain_restype_save_timerfd",
	  offsetof(struct stats_s, chain_restype_save[CHAIN_RESTYPE_TIMERFD]) },
	{ "chain_restype_save_eventfd",
	  offsetof(struct stats_s, chain_restype_save[CHAIN_RESTYPE_EVENTFD]) },
	{ "chain_restype_save_io_uring_fd",
	  offsetof(struct stats_s, chain_restype_save[CHAIN_RESTYPE_IO_URING_FD]) },
	{ "chain_restype_save_pidfd",
	  offsetof(struct stats_s, chain_restype_save[CHAIN_RESTYPE_PIDFD]) },
	{ "chain_restype_save_socket_tcp",
	  offsetof(struct stats_s, chain_restype_save[CHAIN_RESTYPE_SOCKET_TCP]) },
	{ "chain_restype_save_bpf_map_fd",
	  offsetof(struct stats_s, chain_restype_save[CHAIN_RESTYPE_BPF_MAP_FD]) },
	{ "chain_restype_replay_win_epoll_fd",
	  offsetof(struct stats_s, chain_restype_replay_win[CHAIN_RESTYPE_EPOLL_FD]) },
	{ "chain_restype_replay_win_timerfd",
	  offsetof(struct stats_s, chain_restype_replay_win[CHAIN_RESTYPE_TIMERFD]) },
	{ "chain_restype_replay_win_eventfd",
	  offsetof(struct stats_s, chain_restype_replay_win[CHAIN_RESTYPE_EVENTFD]) },
	{ "chain_restype_replay_win_io_uring_fd",
	  offsetof(struct stats_s, chain_restype_replay_win[CHAIN_RESTYPE_IO_URING_FD]) },
	{ "chain_restype_replay_win_pidfd",
	  offsetof(struct stats_s, chain_restype_replay_win[CHAIN_RESTYPE_PIDFD]) },
	{ "chain_restype_replay_win_socket_tcp",
	  offsetof(struct stats_s, chain_restype_replay_win[CHAIN_RESTYPE_SOCKET_TCP]) },
	{ "chain_restype_replay_win_bpf_map_fd",
	  offsetof(struct stats_s, chain_restype_replay_win[CHAIN_RESTYPE_BPF_MAP_FD]) },
	{ "deferred_free_reject_misaligned",
	  offsetof(struct stats_s, deferred_free_reject_misaligned) },
	{ "deferred_free_reject_corrupt_shape",
	  offsetof(struct stats_s, deferred_free_reject_corrupt_shape) },
	{ "deferred_free_reject_non_heap",
	  offsetof(struct stats_s, deferred_free_reject_non_heap) },
	{ "deferred_free_reject_untracked",
	  offsetof(struct stats_s, deferred_free_reject_untracked) },
	{ "nested_scrub_reject_untracked",
	  offsetof(struct stats_s, nested_scrub_reject_untracked) },
	{ "deferred_free_reject_shared_region",
	  offsetof(struct stats_s, deferred_free_reject_shared_region) },
	{ "deferred_free_outstanding_vmas",
	  offsetof(struct stats_s, deferred_free_outstanding_vmas) },
	{ "deferred_free_vma_fallback_immediate",
	  offsetof(struct stats_s, deferred_free_vma_fallback_immediate) },
	{ "deferred_free_enomem_drain",
	  offsetof(struct stats_s, deferred_free_enomem_drain) },
	{ "deferred_free_rw_restore_enomem",
	  offsetof(struct stats_s, deferred_free_rw_restore_enomem) },
	{ "deferred_free_pre_dispatch_leaked",
	  offsetof(struct stats_s, deferred_free_pre_dispatch_leaked) },
	{ "ring_evict_leaked",
	  offsetof(struct stats_s, ring_evict_leaked) },
	{ "deferred_free_ring_owned_skip",
	  offsetof(struct stats_s, deferred_free_ring_owned_skip) },
	{ "deferred_free_double_admit_skip",
	  offsetof(struct stats_s, deferred_free_double_admit_skip) },
	{ "alloc_track_refresh_ring_owned_skip",
	  offsetof(struct stats_s, alloc_track_refresh_ring_owned_skip) },
	{ "alloc_track_refresh_unverified_skip",
	  offsetof(struct stats_s, alloc_track_refresh_unverified_skip) },
	{ "alloc_track_refresh_consume_miss",
	  offsetof(struct stats_s, alloc_track_refresh_consume_miss) },
	{ "pagecache_canary_corrupt_caught",
	  offsetof(struct stats_s, pagecache_canary_corrupt_caught) },
	{ "objpool_array_stale_caught",
	  offsetof(struct stats_s, objpool_array_stale_caught) },
	/* genetlink registry per-family dispatch counters; rate-of-change
	 * surfaces the live family selection mix without waiting for the
	 * end-of-run summary.  A counter that stays at zero across an
	 * interval window with the others advancing flags either a missing
	 * registry entry or a family the controller never resolved. */
	{ "genl_family_calls_devlink",
	  offsetof(struct stats_s, genl_family_calls_devlink) },
	{ "genl_family_calls_nl80211",
	  offsetof(struct stats_s, genl_family_calls_nl80211) },
	{ "genl_family_calls_taskstats",
	  offsetof(struct stats_s, genl_family_calls_taskstats) },
	{ "genl_family_calls_ethtool",
	  offsetof(struct stats_s, genl_family_calls_ethtool) },
	{ "genl_family_calls_mptcp_pm",
	  offsetof(struct stats_s, genl_family_calls_mptcp_pm) },
	{ "genl_family_calls_tipc",
	  offsetof(struct stats_s, genl_family_calls_tipc) },
	{ "genl_family_calls_wireguard",
	  offsetof(struct stats_s, genl_family_calls_wireguard) },
	{ "genl_family_calls_l2tp",
	  offsetof(struct stats_s, genl_family_calls_l2tp) },
	{ "genl_family_calls_gtp",
	  offsetof(struct stats_s, genl_family_calls_gtp) },
	{ "genl_family_calls_macsec",
	  offsetof(struct stats_s, genl_family_calls_macsec) },
	{ "genl_family_calls_netlabel",
	  offsetof(struct stats_s, genl_family_calls_netlabel) },
	{ "genl_family_calls_team",
	  offsetof(struct stats_s, genl_family_calls_team) },
	{ "genl_family_calls_hsr",
	  offsetof(struct stats_s, genl_family_calls_hsr) },
	{ "genl_family_calls_fou",
	  offsetof(struct stats_s, genl_family_calls_fou) },
	{ "genl_family_calls_psample",
	  offsetof(struct stats_s, genl_family_calls_psample) },
	{ "genl_family_calls_nfsd",
	  offsetof(struct stats_s, genl_family_calls_nfsd) },
	{ "genl_family_calls_ila",
	  offsetof(struct stats_s, genl_family_calls_ila) },
	{ "genl_family_calls_ioam6",
	  offsetof(struct stats_s, genl_family_calls_ioam6) },
	{ "genl_family_calls_seg6",
	  offsetof(struct stats_s, genl_family_calls_seg6) },
	{ "genl_family_calls_thermal",
	  offsetof(struct stats_s, genl_family_calls_thermal) },
	{ "genl_family_calls_ipvs",
	  offsetof(struct stats_s, genl_family_calls_ipvs) },
	/* nfnetlink registry per-subsys dispatch counters; same diagnostic
	 * value as the genl ones above but for NETLINK_NETFILTER subsystems.
	 * Lets an operator see the live ctnetlink/nftables/ipset traffic
	 * split at 10-minute granularity without waiting for run end. */
	{ "nfnl_subsys_calls_ctnetlink",
	  offsetof(struct stats_s, nfnl_subsys_calls_ctnetlink) },
	{ "nfnl_subsys_calls_ctnetlink_exp",
	  offsetof(struct stats_s, nfnl_subsys_calls_ctnetlink_exp) },
	{ "nfnl_subsys_calls_nftables",
	  offsetof(struct stats_s, nfnl_subsys_calls_nftables) },
	{ "nfnl_subsys_calls_ipset",
	  offsetof(struct stats_s, nfnl_subsys_calls_ipset) },
	/* UCB1 bandit CMP-novelty reward firings: bumped from
	 * maybe_rotate_strategy() each time the just-finished window had
	 * enough novel comparison constants to clear the integer reward
	 * weight.  Surfaces whether the CMP feedback is meaningfully
	 * contributing to arm selection. */
	{ "bandit_cmp_reward_added",
	  offsetof(struct stats_s, bandit_cmp_reward_added) },
	/* Sibling of bandit_cmp_reward_added for the edge-count secondary
	 * reward.  Fires on windows where pc_edge_count /
	 * EDGE_COUNT_BANDIT_REWARD_WEIGHT_RECIPROCAL was non-zero under
	 * either SHADOW_ONLY or COMBINED; zero on default runs (mode OFF).
	 * Periodic firing rate is the gate the operator watches before
	 * promoting the mode to COMBINED. */
	{ "bandit_edge_count_reward_added",
	  offsetof(struct stats_s, bandit_edge_count_reward_added) },
	/* Picks accepted by STRATEGY_COVERAGE_FRONTIER's frontier-weighted
	 * roulette wheel.  Rate-of-change tracks the arm's actual share of
	 * the fleet's syscall throughput when the bandit picker selects it. */
	{ "frontier_strategy_picks",
	  offsetof(struct stats_s, frontier.strategy_picks) },
	/* Saturating-subtract clamps fired during frontier ring rotation --
	 * see comment on struct field.  Non-zero is a correctness flag, not
	 * tuning data. */
	{ "frontier_underflow_prevented",
	  offsetof(struct stats_s, frontier.underflow_prevented) },
	/* Plateau-intervention rotations that selected the frontier arm.
	 * Held side-channel so the learner-facing bandit_pulls[] stays
	 * clean; the snapshot path folds this back in for the plateau
	 * classifier's frontier_cold rule. */
	{ "frontier_intervention_pulls",
	  offsetof(struct stats_s, frontier.intervention_pulls) },
	/* Accept-regime split of frontier_strategy_picks.  Sum equals
	 * frontier_strategy_picks; the periodic ratio surfaces whether the
	 * picker is steering on the K-window ring (live) or has collapsed
	 * to the lifetime cold-weight fallback (silent). */
	{ "frontier_live_picks",
	  offsetof(struct stats_s, frontier.live_picks) },
	{ "frontier_silent_picks",
	  offsetof(struct stats_s, frontier.silent_picks) },
	/* SHADOW-ONLY decay accounting under the tightened no-novelty
	 * predicate (consecutive silent picks past threshold AND no CMP
	 * insert AND no SUCCESS-bucket errno shift since the streak's
	 * most recent reset).  Sibling of frontier_shadow_decay_candidates;
	 * see the struct-field comment in include/stats.h for the per-
	 * counter semantics. */
	{ "frontier_decay_candidates",
	  offsetof(struct stats_s, frontier.decay_candidates) },
	{ "frontier_decay_would_skip",
	  offsetof(struct stats_s, frontier.decay_would_skip) },
	{ "frontier_silent_decay_live_rejects",
	  offsetof(struct stats_s, frontier.silent_decay_live_rejects) },
	/* SHADOW-ONLY saturation-cooldown predicate accounting (gated by
	 * --frontier-saturation-cooldown != off).  Sibling block of the
	 * silent-streak decay scalars above; this one targets the same
	 * wasteful-silent-pick shape but uses the windowed frontier-edge
	 * ring for plateau and the first-success-TRANSITION + distinct-CMP
	 * spare lanes for the struct-arg backlog.  See the struct-field
	 * comment in include/stats.h for per-counter semantics. */
	{ "frontier_satcool_candidates",
	  offsetof(struct stats_s, frontier.satcool_candidates) },
	{ "frontier_satcool_would_skip",
	  offsetof(struct stats_s, frontier.satcool_would_skip) },
	{ "frontier_satcool_spared_arggen",
	  offsetof(struct stats_s, frontier.satcool_spared_arggen) },
	{ "frontier_satcool_spared_objproducer",
	  offsetof(struct stats_s, frontier.satcool_spared_objproducer) },
	/* SHADOW-ONLY floored-barren sub-floor demote scalars (gated by
	 * --frontier-barren-demote != off).  Sibling of the frontier_
	 * satcool_* scalars above; targets the pure zero-arg getter set
	 * whose lifetime PC-edge yield has plateaued to a hard floor.
	 * See the struct-field comment in include/stats.h for the
	 * per-counter contract. */
	{ "frontier_barren_candidates",
	  offsetof(struct stats_s, frontier.barren_candidates) },
	{ "frontier_barren_would_skip",
	  offsetof(struct stats_s, frontier.barren_would_skip) },
	/* SHADOW-ONLY LIVE-regime cooldown discriminator scalars (gated
	 * by --frontier-live-cooldown-mode != off).  Sibling of the
	 * frontier_satcool_* scalars above; this row projects the
	 * DISCRIMINATED LIVE-regime cooldown demote mass (miss-streak
	 * AND magnitude floor AND no spare lane fires).  Compare against
	 * the undiscriminated frontier_live_would_skip projection for
	 * the over-cool the discriminator removes -- the SHADOW_ONLY
	 * ramp gate. */
	{ "frontier_live_cool_candidates",
	  offsetof(struct stats_s, frontier.live_cool_candidates) },
	{ "frontier_live_cool_would_skip",
	  offsetof(struct stats_s, frontier.live_cool_would_skip) },
	{ "frontier_live_cool_spared_windowed",
	  offsetof(struct stats_s, frontier.live_cool_spared_windowed) },
	{ "frontier_live_cool_spared_arggen",
	  offsetof(struct stats_s, frontier.live_cool_spared_arggen) },
	{ "frontier_live_cool_spared_objproducer",
	  offsetof(struct stats_s, frontier.live_cool_spared_objproducer) },
	/* SHADOW-ONLY Path-A "regular_suppressed" context-axis projection
	 * (gated by --context-pool != off).  See the struct-field comment
	 * in include/stats.h for the per-counter semantics and the enum
	 * context_pool_mode comment in include/strategy.h for the mode
	 * contract.  The (would_skip / candidates) ratio is the projected
	 * regular-pool pick share a live Path-A deactivation would
	 * reclaim; the spared_* triple partitions the spare cascade. */
	{ "context_regular_suppressed_candidates",
	  offsetof(struct stats_s, context_regular_suppressed_candidates) },
	{ "context_regular_suppressed_would_skip",
	  offsetof(struct stats_s, context_regular_suppressed_would_skip) },
	{ "context_regular_suppressed_spared_windowed",
	  offsetof(struct stats_s, context_regular_suppressed_spared_windowed) },
	{ "context_regular_suppressed_spared_arggen",
	  offsetof(struct stats_s, context_regular_suppressed_spared_arggen) },
	{ "context_regular_suppressed_spared_objproducer",
	  offsetof(struct stats_s, context_regular_suppressed_spared_objproducer) },
	/* SHADOW-ONLY LIVE-regime cooldown projections, paired with
	 * frontier_live_miss_streak_per_syscall[].  Candidates is edge-
	 * triggered at FRONTIER_LIVE_MISS_COOLDOWN crossings; would_skip is
	 * cumulative across every LIVE-regime miss past the threshold.  See
	 * the struct-field comments in include/stats.h and the
	 * FRONTIER_LIVE_MISS_COOLDOWN comment in include/strategy.h for the
	 * predicate contract. */
	{ "frontier_live_cooldown_candidates",
	  offsetof(struct stats_s, frontier.live_cooldown_candidates) },
	{ "frontier_live_would_skip",
	  offsetof(struct stats_s, frontier.live_would_skip) },
	/* Did-decay counter for the LIVE-regime early ring-decay path.
	 * Bumped per (nr, rotation) where the early ring-decay in
	 * frontier_window_advance actually halved a non-zero cached sum. */
	{ "frontier_live_cooldown_decays",
	  offsetof(struct stats_s, frontier.live_cooldown_decays) },
	/* Live reject count for the blanket LIVE-regime probabilistic
	 * pick-reject gate.  See the struct-field comment in
	 * include/stats.h and the FRONTIER_LIVE_DECAY_REJECT_DENOM comment
	 * in include/strategy.h for the probabilistic-reject contract. */
	{ "frontier_live_decay_live_rejects",
	  offsetof(struct stats_s, frontier.live_decay_live_rejects) },
	/* SHADOW-ONLY wall-lever accounting.  Eligible_total is
	 * the denominator (every plateau-active pick the lever saw); would_
	 * suppress_total is the projected reclaim count a live variant would
	 * produce.  See the struct-field comment in include/stats.h for the
	 * predicate contract. */
	{ "wall_lever_eligible_total",
	  offsetof(struct stats_s, wall_lever_eligible_total) },
	{ "wall_lever_would_suppress_total",
	  offsetof(struct stats_s, wall_lever_would_suppress_total) },
	/* SHADOW + per-child A/B accounting for the errno-plateau decay at
	 * the coverage-frontier picker's silent-regime accept site.  See the
	 * struct-field comments in include/stats.h and the FRONTIER_ERRNO_
	 * PLATEAU_* contract in include/strategy.h for the per-counter
	 * semantics and the would_skip vs live_rejects vs overlap_silent
	 * triple. */
	{ "frontier_errno_decay_would_skip",
	  offsetof(struct stats_s, frontier.errno_decay_would_skip) },
	{ "frontier_errno_decay_live_rejects",
	  offsetof(struct stats_s, frontier.errno_decay_live_rejects) },
	{ "frontier_errno_decay_overlap_silent",
	  offsetof(struct stats_s, frontier.errno_decay_overlap_silent) },
	/* SHADOW-ONLY A/B scoring for the frontier-blend cold-weight
	 * blend.  The picker still consumes the OLD weight; these counters
	 * expose how often the blended formula would have steered
	 * differently and by how much.  See the struct-field comment in
	 * include/stats.h for the per-counter semantics. */
	{ "frontier_blend_samples",
	  offsetof(struct stats_s, frontier.blend_samples) },
	{ "frontier_blend_new_lower",
	  offsetof(struct stats_s, frontier.blend_new_lower) },
	{ "frontier_blend_new_higher",
	  offsetof(struct stats_s, frontier.blend_new_higher) },
	{ "frontier_blend_new_equal",
	  offsetof(struct stats_s, frontier.blend_new_equal) },
	{ "frontier_blend_old_weight_sum",
	  offsetof(struct stats_s, frontier.blend_old_weight_sum) },
	{ "frontier_blend_new_weight_sum",
	  offsetof(struct stats_s, frontier.blend_new_weight_sum) },
	/* Shadow per-band counters for --reach-band.  All zero on default
	 * (OFF) runs -- the gate in frontier_cold_weight() early-outs
	 * before the bumps.  See the reach_band_* field-comment block in
	 * include/stats.h for SHADOW_ONLY vs COMBINED reading and the
	 * REACH_BAND_IDX_LOW/_MID/_HIGH band semantics. */
	{ "reach_band_picks_low",
	  offsetof(struct stats_s,
		   reach_band_picks_per_band[REACH_BAND_IDX_LOW]) },
	{ "reach_band_picks_mid",
	  offsetof(struct stats_s,
		   reach_band_picks_per_band[REACH_BAND_IDX_MID]) },
	{ "reach_band_picks_high",
	  offsetof(struct stats_s,
		   reach_band_picks_per_band[REACH_BAND_IDX_HIGH]) },
	{ "reach_band_would_demote_mid",
	  offsetof(struct stats_s, reach_band_would_demote_mid) },
	{ "reach_band_would_boost_high",
	  offsetof(struct stats_s, reach_band_would_boost_high) },
	/* Observability for the adaptive expensive-syscall accept gate.
	 * See the expensive_adaptive_* field-comment block in include/
	 * stats.h and the expensive_accept() helper in random-syscall.c
	 * for the OFF / SHADOW_ONLY / COMBINED mode contract. */
	{ "expensive_adaptive_samples",
	  offsetof(struct stats_s, expensive_adaptive_samples) },
	{ "expensive_adaptive_extra_accepts",
	  offsetof(struct stats_s, expensive_adaptive_extra_accepts) },
	{ "expensive_adaptive_demotes",
	  offsetof(struct stats_s, expensive_adaptive_demotes) },
	/* Object-size-relative ARG_LEN draw observability.  All zero while
	 * --arg-len-semantics is off (the default).  See the struct-field
	 * comment block in include/stats.h for per-counter semantics. */
	{ "arg_len_semantics_draws",
	  offsetof(struct stats_s, arg.len_semantics_draws) },
	{ "arg_len_objrelative_used",
	  offsetof(struct stats_s, arg.len_objrelative_used) },
	{ "arg_len_objrelative_nosize",
	  offsetof(struct stats_s, arg.len_objrelative_nosize) },
	{ "arg_len_objrel_blend_getlen",
	  offsetof(struct stats_s, arg.len_objrel_blend_getlen) },
	{ "arg_len_objrel_zero",
	  offsetof(struct stats_s, arg.len_objrel_zero) },
	{ "arg_len_objrel_one",
	  offsetof(struct stats_s, arg.len_objrel_one) },
	{ "arg_len_objrel_objsize",
	  offsetof(struct stats_s, arg.len_objrel_objsize) },
	{ "arg_len_objrel_objsize_minus_1",
	  offsetof(struct stats_s, arg.len_objrel_objsize_minus_1) },
	{ "arg_len_objrel_objsize_half",
	  offsetof(struct stats_s, arg.len_objrel_objsize_half) },
	{ "arg_len_objrel_pagesize",
	  offsetof(struct stats_s, arg.len_objrel_pagesize) },
	{ "arg_len_objrel_pagesize_plus_1",
	  offsetof(struct stats_s, arg.len_objrel_pagesize_plus_1) },
	{ "arg_len_objrel_pagesize_minus_1",
	  offsetof(struct stats_s, arg.len_objrel_pagesize_minus_1) },
	/* Adaptive remote-KCOV mode A/B disposition counters.  Bumped in
	 * lock-step from BOTH arms in remote_adaptive_decide(); the live
	 * remote_mode diverges only on Arm B.  See the struct-field
	 * comments in include/stats.h for per-counter semantics. */
	{ "remote_adaptive_samples",
	  offsetof(struct stats_s, remote_adaptive_samples) },
	{ "remote_adaptive_would_demote",
	  offsetof(struct stats_s, remote_adaptive_would_demote) },
	{ "remote_adaptive_would_promote",
	  offsetof(struct stats_s, remote_adaptive_would_promote) },
	{ "remote_adaptive_would_force",
	  offsetof(struct stats_s, remote_adaptive_would_force) },
	{ "remote_adaptive_would_gate_promote",
	  offsetof(struct stats_s, remote_adaptive_would_gate_promote) },
	{ "remote_adaptive_agree",
	  offsetof(struct stats_s, remote_adaptive_agree) },
	/* Picks the explorer pool forced to STRATEGY_RANDOM.  Rate-of-change
	 * over the run divided by explorer_children gives the per-explorer
	 * picker throughput; deviation from the bandit-pool throughput
	 * highlights either picker overhead or per-strategy work skew. */
	{ "strategy_explorer_picks",
	  offsetof(struct stats_s, strategy_explorer_picks) },
	/* Per-pool new-edge counters: ratio
	 *   explorer_pool_edges_discovered / bandit_pool_edges_discovered
	 * compared against
	 *   explorer_children / (max_children - explorer_children)
	 * tells the operator whether the explorer pool is finding edges
	 * disproportionately to its fleet share -- the trigger condition
	 * for considering per-child bandit (Option C). */
	{ "explorer_pool_edges_discovered",
	  offsetof(struct stats_s, explorer_pool_edges_discovered) },
	{ "bandit_pool_edges_discovered",
	  offsetof(struct stats_s, bandit_pool_edges_discovered) },
	/* Epoll lazy-arm wins: rate-of-change tracks fresh epfds reaching
	 * children after the deferred-arm refactor.  A flat counter while
	 * children are issuing epoll_wait suggests the consumer wireup
	 * regressed. */
	{ "epoll_lazy_armed",
	  offsetof(struct stats_s, epoll_lazy_armed) },
	/* Watch-set populations refused because the candidate fd belonged
	 * to a poll_can_block-tagged fd_provider (FUSE / userfaultfd / KVM
	 * vCPU / io_uring / pidfd).  Sustained growth confirms the filter
	 * is intercepting the fds that would otherwise wedge children in
	 * ep_item_poll → fops->poll on the per-fd waitqueue. */
	{ "epoll_blocking_poll_skipped",
	  offsetof(struct stats_s, epoll_blocking_poll_skipped) },
	/* Per-vCPU ioctl dispatches into kvm_vcpu_grp.  Rate-of-change at the
	 * 10-minute window granularity confirms the OBJ_FD_KVM_VCPU fd_test
	 * path is keeping up with vCPU pool churn -- a flat counter while the
	 * vcpu pool is non-empty would mean the new ioctl group isn't winning
	 * find_ioctl_group() arbitration, or the sanitiser is being bypassed
	 * by a fd that doesn't satisfy kvm_vcpu_fd_test. */
	{ "kvm_vcpu_ioctls_dispatched",
	  offsetof(struct stats_s, kvm_vcpu_ioctls_dispatched) },
	{ "kvm_vm_ioctls_dispatched",
	  offsetof(struct stats_s, kvm_vm_ioctls_dispatched) },
	/* nl80211_churn invocation rate.  Periodic visibility lets an operator
	 * confirm the cfg80211 state-machine fuzzer is making progress under the
	 * mac80211_hwsim radio without waiting for the end-of-run summary; a
	 * flat counter while other network childops advance is the signal that
	 * the hwsim probe latched ns_unsupported_nl80211 and the op went
	 * noop_forever for the rest of the run. */
	{ "nl80211_runs",
	  offsetof(struct stats_s, nl80211_runs) },
	/* SHADOW-ONLY cumulative count of "deep but warm" calls -- no PC-edge
	 * novelty and no CMP-bloom novelty, yet either a per-call PC walk
	 * meaningfully deeper than the syscall's lifetime mean or a trace
	 * that approached the KCOV_TRACE_SIZE buffer cap.  Periodic stats
	 * dump only; the per-syscall warm_reserve_candidates[] breakdown
	 * surfaces via top_syscalls_periodic_dump()'s warm-reserve row. */
	{ "warm_reserve_candidates_total",
	  offsetof(struct stats_s, warm_reserve_candidates_total) },
	/* SHADOW-ONLY intersection of the deep-but-warm predicate above
	 * with the CMP_RISING_PC_FLAT plateau hypothesis -- the would-
	 * replay-demand signal a STAGE B capped-reserve experiment would
	 * size its ring + dispatch path against.  Periodic stats dump
	 * only; the per-syscall warm_reserve_during_plateau[] breakdown
	 * surfaces via top_syscalls_periodic_dump()'s warm-reserve-plateau
	 * row. */
	{ "warm_reserve_during_plateau_total",
	  offsetof(struct stats_s, warm_reserve_during_plateau_total) },
};

static unsigned long periodic_counter_load(unsigned int i)
{
	const char *base = periodic_counter_rates[i].from_aggregate
			   ? (const char *)&parent_stats
			   : (const char *)&shm->stats;
	unsigned long *p = (unsigned long *)(base + periodic_counter_rates[i].off);

	return __atomic_load_n(p, __ATOMIC_RELAXED);
}

void __cold periodic_counter_rates_dump(void)
{
	static unsigned long prev[ARRAY_SIZE(periodic_counter_rates)];
	static struct timespec last_dump;
	struct timespec now;
	unsigned int i;
	long elapsed;
	int header_emitted = 0;

	clock_gettime(CLOCK_MONOTONIC, &now);

	/* First call: arm the window so any pre-existing counts carried
	 * over from earlier in the run are not mis-attributed to the
	 * first window, mirroring corrupt_ptr_spike_check(). */
	if (last_dump.tv_sec == 0) {
		last_dump = now;
		for (i = 0; i < ARRAY_SIZE(periodic_counter_rates); i++)
			prev[i] = periodic_counter_load(i);
		return;
	}

	elapsed = now.tv_sec - last_dump.tv_sec;
	if (elapsed < DEFENSE_DUMP_INTERVAL_SEC)
		return;

	for (i = 0; i < ARRAY_SIZE(periodic_counter_rates); i++) {
		unsigned long cur = periodic_counter_load(i);
		unsigned long delta = sat_sub_ul(cur, prev[i]);
		unsigned long rate_milli;

		prev[i] = cur;
		if (delta == 0)
			continue;

		if (header_emitted == 0) {
			stats_log_write("Periodic counter rates over last %lds:\n",
					elapsed);
			header_emitted = 1;
		}

		/* Per-second rate scaled by 1000 to keep three decimals
		 * without dragging in floating point on the parent path. */
		rate_milli = (delta * 1000UL) / (unsigned long)elapsed;
		stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
				periodic_counter_rates[i].name, delta,
				rate_milli / 1000, rate_milli % 1000, cur);
	}

	corrupt_ptr_attr_dump();
	deferred_free_reject_pc_dump();

	/* Per-fire breadcrumbs printed below the attribution rollup so a
	 * triage scan sees the headline rates, then which handlers, then
	 * the individual scribbled values that drove them.  Self-rate-
	 * limited inside the helper to the same 600 s cadence as the
	 * surrounding dump. */
	corrupt_ptr_breadcrumb_dump(10);

	childop_split_dump();

	/* Advance the per-childop decaying recency ring on the same tick
	 * that drives the other operator-visibility dumps so the recent-
	 * edge / recent-wall view ages out over a wall-clock horizon of
	 * roughly CHILDOP_DECAY_WINDOWS * DEFENSE_DUMP_INTERVAL_SEC.
	 * SHADOW: no picker / canary code reads the ring; rotation cadence
	 * only affects what the shutdown dump labels "recent". */
	childop_window_advance();

	last_dump = now;
}
