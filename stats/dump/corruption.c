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
 * TRINITY_CORRUPT_ATTRIB per-call-site breakdown.  Gated on the
 * env-var-latched bool so production dumps stay terse; when on,
 * emits one stat_row per named site plus a computed "post_generic"
 * row carrying the residual headline - sum(named).  A non-trivial
 * post_generic value is the lead for the next call-site sweep --
 * the producer is some legacy post_handler_corrupt_ptr_bump() macro
 * caller that hasn't been categorised yet.  Reads shm->stats via
 * RELAXED atomic loads since children are concurrent writers.
 */
static void dump_stats_render_corrupt_ptr_attrib(void)
{
	unsigned long named_sum = 0;
	unsigned long total = parent_stats.post_handler_corrupt_ptr;
	unsigned int i;

	for (i = 0; i < CORRUPT_PTR_SITE__COUNT; i++) {
		unsigned long v;
		char metric[64];

		v = __atomic_load_n(&shm->stats.corrupt_ptr.site_count[i],
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
		 sat_sub_ul(total, named_sum));
	output(0, "[main] corrupt_ptr_site:post_generic_cumulative=%lu (headline=%lu named_sum=%lu)\n",
	       sat_sub_ul(total, named_sum),
	       total, named_sum);
}

/* Per-field divergence-sentinel rows: one stat_row per
 * non-zero field shard so the operator sees which
 * monitored field actually drifted rather than a lumped
 * headline number.  Names match the periodic_counter_rates[]
 * registration above so periodic and end-of-run views
 * align. */
static void dump_stats_render_divergence_sentinel(void)
{
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
		unsigned long v = shm->stats.divergence_sentinel.anomalies[f];

		if (v == 0)
			continue;
		stat_row("corruption",
			 divergence_sentinel_rows[s].name, v);
	}
}

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
static void dump_stats_render_maps_pick_ratios(void)
{
	unsigned long s  = shm->stats.maps.pick_successes;
	unsigned long a  = shm->stats.maps.pick_attempts_sum;
	unsigned long ps = shm->stats.maps.pick_with_prot_successes;
	unsigned long pa = shm->stats.maps.pick_with_prot_attempts_sum;
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

/*
 * Render the SAMPLED get_map_handle() pick-cost shadow telemetry
 * added alongside the maps_pick_attempts ratio: a log2 histogram of
 * the reject-loop exit index (bumped on both success and exhaustion
 * paths) and the mean cycles-per-call derived from the rdtsc
 * sample-sum / sample-count pair.  Bucket layout mirrors
 * fd_live_remove_scan_histogram exactly; the row labels use the
 * same _hist_<lo>_<hi> / _hist_ge<max> shape.  Zero buckets are
 * skipped to keep the dump readable when a run never hits them, and
 * the cycles-per-call row is skipped when the sample denominator is
 * zero (no sampled calls yet, or non-x86 non-aarch64 target where
 * maps_pick_read_cycles() returns 0).
 */
static void dump_stats_render_maps_pick_shadow(void)
{
	static const char *const bucket_names[8] = {
		"maps_pick_scan_hist_0",
		"maps_pick_scan_hist_1",
		"maps_pick_scan_hist_2_3",
		"maps_pick_scan_hist_4_7",
		"maps_pick_scan_hist_8_15",
		"maps_pick_scan_hist_16_31",
		"maps_pick_scan_hist_32_63",
		"maps_pick_scan_hist_ge64",
	};
	unsigned long cyc_sum   = shm->stats.maps.pick_cycles_sampled_sum;
	unsigned long cyc_count = shm->stats.maps.pick_cycles_sampled_count;
	unsigned int b;

	for (b = 0; b < ARRAY_SIZE(bucket_names); b++) {
		unsigned long v = shm->stats.maps.pick_scan_histogram[b];

		if (v == 0)
			continue;
		stat_row("pool", bucket_names[b], v);
	}

	if (cyc_count > 0) {
		char val[32];
		unsigned long milli = ((cyc_sum % cyc_count) * 1000UL) / cyc_count;

		snprintf(val, sizeof(val), "%lu.%03lu",
			 cyc_sum / cyc_count, milli);
		output(0, STATS_HDR_FMT, "pool",
		       "maps_pick_cycles_per_call_sampled", val);
	}
}

/*
 * Ring health: surface the parent-side stats_ring drain accounting so
 * operators can tell whether children are enqueuing faster than the
 * parent drains (ring_overflow_delta > 0 window-over-window) and how
 * widely the pressure is spread (ring_overflow_child_permille).  All
 * counters are cumulative and parent-write-only; the render reads them
 * with __ATOMIC_RELAXED to match the sibling corruption rows.  The
 * delta row uses a function-local static: this helper runs only on
 * dump_stats() ticks, which are single-threaded parent context.
 */
static void dump_stats_render_ring_health(void)
{
	static unsigned long prev_overflow_total;
	unsigned long overflow_total, slots_total, visited, overflow_events;
	unsigned long delta;

	overflow_total = __atomic_load_n(&parent_stats.ring_overflow_total,
					 __ATOMIC_RELAXED);
	slots_total = __atomic_load_n(&parent_stats.ring_slots_processed_total,
				      __ATOMIC_RELAXED);
	visited = __atomic_load_n(&parent_stats.ring_drain_children_visited,
				  __ATOMIC_RELAXED);
	overflow_events = __atomic_load_n(&parent_stats.ring_children_overflow_events,
					  __ATOMIC_RELAXED);

	if (visited == 0)
		return;

	delta = sat_sub_ul(overflow_total, prev_overflow_total);
	prev_overflow_total = overflow_total;

	stat_row("ring_health", "ring_overflow_total",           overflow_total);
	stat_row("ring_health", "ring_overflow_delta",           delta);
	stat_row("ring_health", "ring_slots_processed_total",    slots_total);
	stat_row("ring_health", "ring_drain_children_visited",   visited);
	stat_row("ring_health", "ring_slots_per_child_mean",     slots_total / visited);
	stat_row("ring_health", "ring_children_overflow_events", overflow_events);
	stat_row("ring_health", "ring_overflow_child_permille",
		 overflow_events * 1000UL / visited);
}

static void dump_stats_render_ring_corruption(void)
{
	if (shm->stats.fd.event_ring_corrupted)
		stat_row("corruption", "fd_event_ring_noncanon", shm->stats.fd.event_ring_corrupted);
	if (shm->stats.fd.event_ring_overwritten)
		stat_row("corruption", "fd_event_ring_canary",   shm->stats.fd.event_ring_overwritten);
	if (shm->stats.stats_ring_corrupted)
		stat_row("corruption", "stats_ring_noncanon",    shm->stats.stats_ring_corrupted);
	if (shm->stats.stats_ring_overwritten)
		stat_row("corruption", "stats_ring_canary",      shm->stats.stats_ring_overwritten);
	if (shm->stats.fd.event_payload_corrupt)
		stat_row("corruption", "fd_event_payload",       shm->stats.fd.event_payload_corrupt);
	dump_stats_render_ring_health();
}

static void dump_stats_render_corrupt_ptr_family(void)
{
	if (parent_stats.deferred_free_corrupt_ptr)
		stat_row("corruption", "deferred_free_corrupt_ptr", parent_stats.deferred_free_corrupt_ptr);
	if (parent_stats.post_handler_corrupt_ptr)
		stat_row("corruption", "post_handler_corrupt_ptr", parent_stats.post_handler_corrupt_ptr);
	if (parent_stats.validator_rejected)
		stat_row("corruption", "validator_rejected", parent_stats.validator_rejected);
	if (shm->stats.epoll_volatility.wait_null_events_alloc_fail)
		stat_row("corruption", "epoll_wait_null_events_alloc_fail",
			 shm->stats.epoll_volatility.wait_null_events_alloc_fail);
	if (shm->stats.epoll_volatility.wait_null_events_shared_reject)
		stat_row("corruption", "epoll_wait_null_events_shared_reject",
			 shm->stats.epoll_volatility.wait_null_events_shared_reject);
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
	output(0, "[main] validator_rejected_cumulative=%lu\n",
	       parent_stats.validator_rejected);
	if (corrupt_ptr_attrib_active())
		dump_stats_render_corrupt_ptr_attrib();
	if (parent_stats.arg_shadow_stomp)
		stat_row("corruption", "arg_shadow_stomp", parent_stats.arg_shadow_stomp);
}

static void dump_stats_render_deferred_free_rejects(void)
{
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
	if (shm->stats.alloc_track_refresh_consume_miss)
		stat_row("corruption", "alloc_track_refresh_consume_miss",    shm->stats.alloc_track_refresh_consume_miss);
	if (shm->stats.rec_owned_overflow_to_ring)
		stat_row("corruption", "rec_owned_overflow_to_ring",          shm->stats.rec_owned_overflow_to_ring);
}

static void dump_stats_render_post_state_release_rejects(void)
{
	if (shm->stats.post_state_release_reject_untracked)
		stat_row("corruption", "post_state_release_reject_untracked",
			 shm->stats.post_state_release_reject_untracked);
	if (shm->stats.post_state_release_reject_released)
		stat_row("corruption", "post_state_release_reject_released",
			 shm->stats.post_state_release_reject_released);
	if (shm->stats.post_state_release_reject_wrong_owner)
		stat_row("corruption", "post_state_release_reject_wrong_owner",
			 shm->stats.post_state_release_reject_wrong_owner);
	if (shm->stats.post_state_release_reject_bad_magic)
		stat_row("corruption", "post_state_release_reject_bad_magic",
			 shm->stats.post_state_release_reject_bad_magic);
}

static void dump_stats_render_scribble_canary_blanket(void)
{
	if (parent_stats.snapshot_non_heap_reject)
		stat_row("corruption", "snapshot_non_heap_reject", parent_stats.snapshot_non_heap_reject);
	if (parent_stats.lock_word_scribbled)
		stat_row("corruption", "lock_word_scribbled",   parent_stats.lock_word_scribbled);
	if (shm->stats.lock_held_scribble)
		stat_row("corruption", "lock_held_scribble",    shm->stats.lock_held_scribble);
	if (shm->stats.rec_canary_stomped)
		stat_row("corruption", "rec_canary_stomped",     shm->stats.rec_canary_stomped);
	if (shm->stats.plateau.mut_attrib_inversion_caught)
		stat_row("corruption", "mut_attrib_inversion_caught",
			 shm->stats.plateau.mut_attrib_inversion_caught);
	if (shm->stats.rzs_blanket_reject)
		stat_row("corruption", "rzs_blanket_reject",     shm->stats.rzs_blanket_reject);
	if (shm->stats.retfd_blanket_reject)
		stat_row("corruption", "retfd_blanket_reject",   shm->stats.retfd_blanket_reject);
}

static void dump_stats_render_arena_ptr_stale_and_sentinel(void)
{
	if (shm->stats.arena_ptr_stale_caught_arg)
		stat_row("corruption", "arena_ptr_stale_caught_arg",
			 shm->stats.arena_ptr_stale_caught_arg);
	if (shm->stats.arena_ptr_stale_caught_post_state)
		stat_row("corruption", "arena_ptr_stale_caught_post_state",
			 shm->stats.arena_ptr_stale_caught_post_state);
	/*
	 * Standalone grep-friendly cumulative lines for the arena_ptr_stale
	 * pair.  The stat_rows above are gated on non-zero, and the JSON +
	 * periodic_counter_rates[] registrations repeat the bare counter tokens as
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
	dump_stats_render_divergence_sentinel();
	if (shm->stats.divergence_sentinel.expected_drift)
		stat_row("corruption", "divergence_sentinel_expected_drift",
			 shm->stats.divergence_sentinel.expected_drift);
	if (shm->stats.destroy_object_idx_corrupt)
		stat_row("corruption", "destroy_object_idx",     shm->stats.destroy_object_idx_corrupt);
	if (shm->stats.global_obj_uaf_caught)
		stat_row("corruption", "global_obj_uaf_caught",  shm->stats.global_obj_uaf_caught);
}

static void dump_stats_render_maps_pool_rejects(void)
{
	if (shm->stats.maps.pool_draw_exhausted)
		stat_row("pool", "maps_pool_draw_exhausted",   shm->stats.maps.pool_draw_exhausted);
	if (shm->stats.maps.reject_pool_empty)
		stat_row("pool", "maps_reject_pool_empty",     shm->stats.maps.reject_pool_empty);
	if (shm->stats.maps.reject_bogus_obj_ptr)
		stat_row("pool", "maps_reject_bogus_obj_ptr",  shm->stats.maps.reject_bogus_obj_ptr);
	if (shm->stats.maps.reject_alloc_track_miss)
		stat_row("pool", "maps_reject_alloc_track_miss", shm->stats.maps.reject_alloc_track_miss);
	if (shm->stats.maps.reject_alloc_track_miss_anon)
		stat_row("pool", "maps_reject_alloc_track_miss_anon",
			 shm->stats.maps.reject_alloc_track_miss_anon);
	if (shm->stats.maps.reject_alloc_track_miss_file)
		stat_row("pool", "maps_reject_alloc_track_miss_file",
			 shm->stats.maps.reject_alloc_track_miss_file);
	if (shm->stats.maps.reject_alloc_track_miss_testfile)
		stat_row("pool", "maps_reject_alloc_track_miss_testfile",
			 shm->stats.maps.reject_alloc_track_miss_testfile);
	if (shm->stats.maps.reject_size_zero)
		stat_row("pool", "maps_reject_size_zero",      shm->stats.maps.reject_size_zero);
	if (shm->stats.maps.reject_size_too_large)
		stat_row("pool", "maps_reject_size_too_large", shm->stats.maps.reject_size_too_large);
}

static void dump_stats_render_late_corruption_oracle(void)
{
	if (shm->stats.chain_replay_len_corrupt)
		stat_row("corruption", "chain_replay_len_corrupt", shm->stats.chain_replay_len_corrupt);
	if (shm->stats.pagecache_canary_corrupt_caught)
		stat_row("oracle", "pagecache_canary_corrupt_caught",
			 shm->stats.pagecache_canary_corrupt_caught);
	if (shm->stats.objpool_array_stale_caught)
		stat_row("corruption", "objpool_array_stale_caught",
			 shm->stats.objpool_array_stale_caught);
}

void dump_stats_corruption_and_pool(void)
{
	dump_stats_render_ring_corruption();
	dump_stats_render_corrupt_ptr_family();
	dump_stats_render_deferred_free_rejects();
	dump_stats_render_post_state_release_rejects();
	dump_stats_render_scribble_canary_blanket();
	dump_stats_render_arena_ptr_stale_and_sentinel();
	dump_stats_render_maps_pool_rejects();
	dump_stats_render_late_corruption_oracle();

	dump_stats_render_maps_pick_ratios();
	dump_stats_render_maps_pick_shadow();
}
