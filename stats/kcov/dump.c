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


static void dump_stats_render_kcov_transition_edges(void)
{
		unsigned long kc_tedges = __atomic_load_n(
			&kcov_shm->transitions.transition_edges_found,
			__ATOMIC_RELAXED);
		unsigned long kc_tdistinct = __atomic_load_n(
			&kcov_shm->transitions.transition_distinct_edges,
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

static void dump_stats_render_kcov_cmp_hint_tier(void)
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

static void dump_stats_render_kcov_warm_known_hits(void)
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

static void dump_stats_render_kcov_reexec(void)
{
		unsigned long rx_attempts = __atomic_load_n(&kcov_shm->reexec_flat.reexec_attempts, __ATOMIC_RELAXED);
		unsigned long rx_attribution_found = __atomic_load_n(&kcov_shm->reexec_flat.reexec_attribution_found, __ATOMIC_RELAXED);
		unsigned long rx_attribution_ambiguous = __atomic_load_n(&kcov_shm->reexec_flat.reexec_attribution_ambiguous, __ATOMIC_RELAXED);
		unsigned long rx_attribution_width_match = __atomic_load_n(&kcov_shm->reexec_flat.reexec_attribution_width_match, __ATOMIC_RELAXED);
		unsigned long rx_new_cmps_total = __atomic_load_n(&kcov_shm->reexec_flat.reexec_new_cmps_total, __ATOMIC_RELAXED);
		unsigned long rx_skipped_destructive = __atomic_load_n(&kcov_shm->reexec_flat.reexec_skipped_destructive, __ATOMIC_RELAXED);
		unsigned long rx_skipped_validate_silent = __atomic_load_n(&kcov_shm->reexec_flat.reexec_skipped_validate_silent, __ATOMIC_RELAXED);
		unsigned long rx_window_cap_hit = __atomic_load_n(&kcov_shm->reexec_flat.reexec_window_cap_hit, __ATOMIC_RELAXED);
		unsigned long rx_parent_calls_enabled = __atomic_load_n(&kcov_shm->cmp_parent.cmp_parent_calls_enabled, __ATOMIC_RELAXED);
		unsigned long rx_parent_calls_control = __atomic_load_n(&kcov_shm->cmp_parent.cmp_parent_calls_control, __ATOMIC_RELAXED);
		unsigned long rx_parent_new_cmps_enabled = __atomic_load_n(&kcov_shm->cmp_parent.cmp_parent_new_cmps_enabled, __ATOMIC_RELAXED);
		unsigned long rx_parent_new_cmps_control = __atomic_load_n(&kcov_shm->cmp_parent.cmp_parent_new_cmps_control, __ATOMIC_RELAXED);
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

static void dump_stats_render_kcov_ring_replay(void)
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

static void dump_stats_render_kcov_cmp_field_consumer(void)
{
		unsigned long fc_would_pick = __atomic_load_n(&kcov_shm->cmp_field_consumer_would_pick, __ATOMIC_RELAXED);
		unsigned long fc_would_differs = __atomic_load_n(&kcov_shm->cmp_field_consumer_would_value_differs, __ATOMIC_RELAXED);
		unsigned long fc_would_miss = __atomic_load_n(&kcov_shm->cmp_field_consumer_would_miss, __ATOMIC_RELAXED);
		unsigned long fc_key_absent = __atomic_load_n(&kcov_shm->cmp_field_consumer_key_absent, __ATOMIC_RELAXED);
		unsigned long fc_pool_corrupt = __atomic_load_n(&kcov_shm->cmp_field_consumer_pool_corrupted, __ATOMIC_RELAXED);
		unsigned long fc_live_picks = __atomic_load_n(&kcov_shm->cmp_field_consumer_live_picks, __ATOMIC_RELAXED);
		unsigned long fc_g_variant = __atomic_load_n(&kcov_shm->cmp_field_consumer_guard_variant_layout, __ATOMIC_RELAXED);
		unsigned long fc_g_bufdisc = __atomic_load_n(&kcov_shm->cmp_field_consumer_guard_buffer_discrim, __ATOMIC_RELAXED);
		unsigned long fc_g_lenpair = __atomic_load_n(&kcov_shm->cmp_field_consumer_guard_len_pair, __ATOMIC_RELAXED);
		unsigned long fc_g_nested = __atomic_load_n(&kcov_shm->cmp_field_consumer_guard_nested_pointer, __ATOMIC_RELAXED);
		unsigned long fc_g_dep = __atomic_load_n(&kcov_shm->cmp_field_consumer_guard_dependent, __ATOMIC_RELAXED);
		unsigned long fc_p_elig = __atomic_load_n(&kcov_shm->cmp_field_consumer_prove_eligible, __ATOMIC_RELAXED);
		unsigned long fc_p_edges = __atomic_load_n(&kcov_shm->cmp_field_consumer_prove_edges_at_pick, __ATOMIC_RELAXED);
		unsigned long fc_p_cmps = __atomic_load_n(&kcov_shm->cmp_field_consumer_prove_cmp_records_at_pick, __ATOMIC_RELAXED);
		unsigned long fc_p_einval = __atomic_load_n(&kcov_shm->cmp_field_consumer_prove_einval_at_pick, __ATOMIC_RELAXED);

		if (fc_would_pick > 0)
			stat_row("kcov_coverage", "cmp_field_consumer_would_pick", fc_would_pick);
		if (fc_would_differs > 0)
			stat_row("kcov_coverage", "cmp_field_consumer_would_value_differs", fc_would_differs);
		if (fc_would_miss > 0)
			stat_row("kcov_coverage", "cmp_field_consumer_would_miss", fc_would_miss);
		if (fc_key_absent > 0)
			stat_row("kcov_coverage", "cmp_field_consumer_key_absent", fc_key_absent);
		if (fc_pool_corrupt > 0)
			stat_row("kcov_coverage", "cmp_field_consumer_pool_corrupted", fc_pool_corrupt);
		if (fc_live_picks > 0)
			stat_row("kcov_coverage", "cmp_field_consumer_live_picks", fc_live_picks);
		if (fc_g_variant > 0)
			stat_row("kcov_coverage", "cmp_field_consumer_guard_variant_layout", fc_g_variant);
		if (fc_g_bufdisc > 0)
			stat_row("kcov_coverage", "cmp_field_consumer_guard_buffer_discrim", fc_g_bufdisc);
		if (fc_g_lenpair > 0)
			stat_row("kcov_coverage", "cmp_field_consumer_guard_len_pair", fc_g_lenpair);
		if (fc_g_nested > 0)
			stat_row("kcov_coverage", "cmp_field_consumer_guard_nested_pointer", fc_g_nested);
		if (fc_g_dep > 0)
			stat_row("kcov_coverage", "cmp_field_consumer_guard_dependent", fc_g_dep);
		if (fc_p_elig > 0)
			stat_row("kcov_coverage", "cmp_field_consumer_prove_eligible", fc_p_elig);
		if (fc_p_edges > 0)
			stat_row("kcov_coverage", "cmp_field_consumer_prove_edges_at_pick", fc_p_edges);
		if (fc_p_cmps > 0)
			stat_row("kcov_coverage", "cmp_field_consumer_prove_cmp_records_at_pick", fc_p_cmps);
		if (fc_p_einval > 0)
			stat_row("kcov_coverage", "cmp_field_consumer_prove_einval_at_pick", fc_p_einval);
}

static void dump_stats_render_kcov_exit_edge_delta(void)
{
		unsigned long rc_inserts = __atomic_load_n(&kcov_shm->cmp_recent_inserts, __ATOMIC_RELAXED);
		unsigned long rc_evicts = __atomic_load_n(&kcov_shm->cmp_recent_evicts, __ATOMIC_RELAXED);
		unsigned long rc_would_pick = __atomic_load_n(&kcov_shm->cmp_recent_would_pick, __ATOMIC_RELAXED);
		unsigned long rc_would_miss = __atomic_load_n(&kcov_shm->cmp_recent_would_miss, __ATOMIC_RELAXED);
		unsigned long rc_live_picks = __atomic_load_n(&kcov_shm->cmp_recent_live_picks, __ATOMIC_RELAXED);
		unsigned long st_ips = __atomic_load_n(&kcov_shm->cmp_shared_tier_ips, __ATOMIC_RELAXED);
		unsigned long st_entries = __atomic_load_n(&kcov_shm->cmp_shared_tier_entries, __ATOMIC_RELAXED);
		unsigned long st_excluded = __atomic_load_n(&kcov_shm->cmp_shared_tier_entry_path_excluded_ips, __ATOMIC_RELAXED);
		unsigned long st_eligible = __atomic_load_n(&kcov_shm->cmp_shared_tier_shadow_warmstart_eligible, __ATOMIC_RELAXED);
		unsigned long st_would_confirm = __atomic_load_n(&kcov_shm->cmp_shared_tier_shadow_would_confirm, __ATOMIC_RELAXED);
		unsigned long st_supplied = __atomic_load_n(&kcov_shm->cmp_shared_tier_shadow_dedup_supplied, __ATOMIC_RELAXED);

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
		if (st_ips > 0)
			stat_row("kcov_coverage", "cmp_shared_tier_ips", st_ips);
		if (st_entries > 0)
			stat_row("kcov_coverage", "cmp_shared_tier_entries", st_entries);
		if (st_excluded > 0)
			stat_row("kcov_coverage", "cmp_shared_tier_entry_path_excluded_ips", st_excluded);
		if (st_eligible > 0)
			stat_row("kcov_coverage", "cmp_shared_tier_shadow_warmstart_eligible", st_eligible);
		if (st_would_confirm > 0)
			stat_row("kcov_coverage", "cmp_shared_tier_shadow_would_confirm", st_would_confirm);
		if (st_supplied > 0)
			stat_row("kcov_coverage", "cmp_shared_tier_shadow_dedup_supplied", st_supplied);
}

static void dump_stats_render_kcov_exit_edge_totals(void)
{
		unsigned long plateau_entered_v = __atomic_load_n(&shm->stats.plateau.entered, __ATOMIC_RELAXED);
		unsigned long plateau_exited_v = __atomic_load_n(&shm->stats.plateau.exited, __ATOMIC_RELAXED);
		unsigned long bucket_canary_checks_v = __atomic_load_n(&shm->stats.plateau.bucket_canary_checks, __ATOMIC_RELAXED);
		unsigned long bucket_canary_deficits_v = __atomic_load_n(&shm->stats.plateau.bucket_canary_deficits, __ATOMIC_RELAXED);

		if (plateau_entered_v > 0)
			stat_row("kcov_coverage", "plateau_entered", plateau_entered_v);
		if (plateau_exited_v > 0)
			stat_row("kcov_coverage", "plateau_exited", plateau_exited_v);
		if (bucket_canary_checks_v > 0)
			stat_row("kcov_coverage", "bucket_canary_checks", bucket_canary_checks_v);
		if (bucket_canary_deficits_v > 0)
			stat_row("kcov_coverage", "bucket_canary_deficits", bucket_canary_deficits_v);
}

static void dump_stats_render_kcov_per_syscall_edges_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int delta_nr[10];
		unsigned long delta_edges[10];
		unsigned int delta_count = 0;
		bool any_delta = false;

		memset(delta_edges, 0, sizeof(delta_edges));
		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long prev = per_syscall_edges_previous_total(i);
			unsigned long curr = per_syscall_edges_total(i);
			unsigned long delta = sat_sub_ul(curr, prev);

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

		/* Snapshot current counts for the next interval.  Both arch
		 * slots are snapshotted so the [nr][arch] delta stays a pure
		 * subtraction on the next window. */
		for (i = 0; i < nr_syscalls_to_scan; i++) {
			kcov_shm->per_syscall.per_syscall_edges_previous[i][0] =
				__atomic_load_n(
					&kcov_shm->per_syscall.per_syscall_edges[i][0],
					__ATOMIC_RELAXED);
			kcov_shm->per_syscall.per_syscall_edges_previous[i][1] =
				__atomic_load_n(
					&kcov_shm->per_syscall.per_syscall_edges[i][1],
					__ATOMIC_RELAXED);
		}
}

/*
 * SHADOW-only Phase-1 per-syscall attribution-confidence diagnostic
 * dump.  Silent when frontier_noise_sample == 0 (feature off => no
 * samples collected => no rows to render) or when kcov_shm is
 * unavailable.  Prints a top-N by sampled noisy-window count of the
 * per-syscall clean numerator, the sampled global-delta denominator
 * (scaled back up by N so the reported figure estimates the full-
 * population delta), the resulting attribution-confidence ratio
 * (clean_frac = clean / est_noisy, clamped denominator), the local-
 * only clean subset (clean - clean_remote), and the spare-cascade
 * lane the frontier picker would use for this syscall.  Purely
 * observational -- no counter reset, no back-pressure on selection.
 * The spare-lane column consumes frontier_spare_lane_decide from
 * include/strategy.h so this dump and the cooldown helpers stay in
 * lockstep on how a syscall is classified.
 */
static void dump_stats_render_kcov_per_syscall_noisy_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;
	unsigned int noisy_sample_n;
	unsigned int top_nr[10];
	unsigned long top_samples[10];
	unsigned int top_count = 0;
	bool any_samples = false;

	noisy_sample_n = __atomic_load_n(&frontier_noise_sample,
					 __ATOMIC_RELAXED);
	if (noisy_sample_n == 0 || kcov_shm == NULL)
		return;

	memset(top_samples, 0, sizeof(top_samples));
	for (i = 0; i < nr_syscalls_to_scan; i++) {
		unsigned long samples = __atomic_load_n(
			&kcov_shm->per_syscall.per_syscall_noisy_samples[i],
			__ATOMIC_RELAXED);

		if (samples == 0)
			continue;
		any_samples = true;
		topn_push(top_samples, top_nr, &top_count, 10, samples, i);
	}

	if (!any_samples || top_count == 0)
		return;

	output(0, "Top syscalls by sampled noisy attribution (N=%u, SHADOW):\n",
	       noisy_sample_n);
	output(0, "  %-24s %10s %10s %14s %14s %14s %10s\n",
	       "name", "samples", "clean", "est_noisy",
	       "clean/est_noisy", "clean_local", "spare_lane");
	for (j = 0; j < top_count; j++) {
		struct syscallentry *entry = table[top_nr[j]].entry;
		const char *name = entry ? entry->name : "???";
		unsigned int nr = top_nr[j];
		unsigned long samples = top_samples[j];
		unsigned long clean = per_syscall_edges_total(nr);
		unsigned long clean_remote = __atomic_load_n(
			&kcov_shm->per_syscall.per_syscall_edges_clean_remote[nr],
			__ATOMIC_RELAXED);
		unsigned long noisy_raw = __atomic_load_n(
			&kcov_shm->per_syscall.per_syscall_edges_noisy[nr],
			__ATOMIC_RELAXED);
		unsigned long est_noisy;
		unsigned long clean_local;
		unsigned long frac_permille;
		enum frontier_spare_reason reason;
		const char *lane;

		/* Scale the sampled delta sum back up by N to estimate the
		 * full-population noisy denominator.  samples is guaranteed
		 * non-zero on the topn path. */
		est_noisy = (noisy_raw * (unsigned long) noisy_sample_n) / samples;
		clean_local = (clean >= clean_remote) ? (clean - clean_remote) : 0UL;
		/* Report clean / max(1, est_noisy) as permille (three-digit
		 * fraction so a 12.3% confidence renders as "123"), matching
		 * the tt_call_str shape used in the truncation top-N dump. */
		{
			unsigned long denom = est_noisy > 0 ? est_noisy : 1UL;

			frac_permille = (clean * 1000UL) / denom;
		}
		/* Read the spare-cascade lane for the 64-bit slot (do32=false)
		 * -- the diagnostic dump does not split by arch elsewhere and
		 * the 64-bit slot is the dominant caller for every non-IA32-
		 * only syscall.  Callers reading a biarch nr's IA32 side can
		 * still cross-reference the arch split via per_syscall_edges
		 * total. */
		reason = frontier_spare_lane_decide(nr, false);
		switch (reason) {
		case FRONTIER_SPARE_WINDOWED_EDGES: lane = "windowed"; break;
		case FRONTIER_SPARE_ARGGEN:         lane = "arggen"; break;
		case FRONTIER_SPARE_OBJPRODUCER:    lane = "objprod"; break;
		default:                            lane = "none"; break;
		}

		output(0, "  %-24s %10lu %10lu %14lu %11lu.%1lu%% %14lu %10s\n",
		       name, samples, clean, est_noisy,
		       frac_permille / 10, frac_permille % 10,
		       clean_local, lane);
	}
}

static void dump_stats_render_kcov_per_syscall_calls_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int tr_top_nr[10];
		unsigned long tr_top_edges[10];
		unsigned int tr_top_count = 0;
		bool any_tr = false;

		memset(tr_top_edges, 0, sizeof(tr_top_edges));
		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long tedges = __atomic_load_n(
				&kcov_shm->transitions.per_syscall_transition_edges_real[i],
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

static void dump_stats_render_kcov_per_syscall_edge_calls_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int tr_delta_nr[10];
		unsigned long tr_delta_edges[10];
		unsigned int tr_delta_count = 0;
		bool any_tr_delta = false;

		memset(tr_delta_edges, 0, sizeof(tr_delta_edges));
		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long prev = kcov_shm->transitions.per_syscall_transition_edges_previous[i];
			unsigned long curr = __atomic_load_n(
				&kcov_shm->transitions.per_syscall_transition_edges[i],
				__ATOMIC_RELAXED);
			unsigned long delta = sat_sub_ul(curr, prev);

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
			kcov_shm->transitions.per_syscall_transition_edges_previous[i] =
				__atomic_load_n(
					&kcov_shm->transitions.per_syscall_transition_edges[i],
					__ATOMIC_RELAXED);
}

static void dump_stats_render_kcov_per_syscall_cold_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int cmp_delta_nr[10];
		unsigned long cmp_delta_inserts[10];
		unsigned int cmp_delta_count = 0;
		bool any_cmp_delta = false;

		memset(cmp_delta_inserts, 0, sizeof(cmp_delta_inserts));
		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long prev = kcov_shm->per_syscall_cmp.per_syscall_cmp_inserts_previous[i];
			unsigned long curr = __atomic_load_n(&kcov_shm->per_syscall_cmp.per_syscall_cmp_inserts[i], __ATOMIC_RELAXED);
			unsigned long delta = sat_sub_ul(curr, prev);

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
			kcov_shm->per_syscall_cmp.per_syscall_cmp_inserts_previous[i] =
				__atomic_load_n(&kcov_shm->per_syscall_cmp.per_syscall_cmp_inserts[i], __ATOMIC_RELAXED);
}

static void dump_stats_render_kcov_per_syscall_yield_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

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
				buckets[b] = __atomic_load_n(&kcov_shm->errno_state.per_syscall_errno[i][b],
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

static void dump_stats_render_kcov_kcov_dispatch_stats(void)
{
		bool any = false;
		unsigned int c;

		for (c = 0; c < CRED_CLASS_NR; c++) {
			if (__atomic_load_n(&shm->stats.cred_class.calls[c],
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
					&shm->stats.cred_class.calls[c],
					__ATOMIC_RELAXED);
				unsigned long succ = __atomic_load_n(
					&shm->stats.cred_class.success[c],
					__ATOMIC_RELAXED);
				unsigned long eperm = __atomic_load_n(
					&shm->stats.cred_class.eperm[c],
					__ATOMIC_RELAXED);
				unsigned long einval = __atomic_load_n(
					&shm->stats.cred_class.einval[c],
					__ATOMIC_RELAXED);
				unsigned long thr = __atomic_load_n(
					&shm->stats.cred_class.throttled[c],
					__ATOMIC_RELAXED);

				if (calls == 0 && thr == 0)
					continue;
				output(0, "  %-12s %10lu %10lu %10lu %10lu %10lu\n",
				       cred_class_name[c], calls,
				       succ, eperm, einval, thr);
			}
		}
}

static void dump_stats_render_kcov_per_syscall_dedup_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int lr_top_nr[10];
		unsigned long lr_top_total[10];
		unsigned int lr_top_count = 0;

		memset(lr_top_total, 0, sizeof(lr_top_total));
		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long lc = __atomic_load_n(
				&kcov_shm->pc_ctx.local_pc_calls[i],
				__ATOMIC_RELAXED);
			unsigned long rc = __atomic_load_n(
				&kcov_shm->pc_ctx.remote_pc_calls[i],
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
					&kcov_shm->pc_ctx.local_pc_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long lec = __atomic_load_n(
					&kcov_shm->pc_ctx.local_pc_edge_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long len_ = __atomic_load_n(
					&kcov_shm->pc_ctx.local_pc_edge_count[nr],
					__ATOMIC_RELAXED);
				unsigned long rc = __atomic_load_n(
					&kcov_shm->pc_ctx.remote_pc_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long rec = __atomic_load_n(
					&kcov_shm->pc_ctx.remote_pc_edge_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long ren = __atomic_load_n(
					&kcov_shm->pc_ctx.remote_pc_edge_count[nr],
					__ATOMIC_RELAXED);

				output(0, "  %-24s %10lu %10lu %10lu %10lu %10lu %10lu\n",
				       name, lc, lec, len_, rc, rec, ren);
			}
		}
}

static void dump_stats_render_kcov_kcov_probe_costs(void)
{
	unsigned int j;

		unsigned int lr_top_op[10];
		unsigned long lr_top_total[10];
		unsigned int lr_top_count = 0;
		unsigned int op;

		memset(lr_top_total, 0, sizeof(lr_top_total));
		for (op = 0; op < KCOV_CHILDOP_NR_MAX; op++) {
			unsigned long lc = __atomic_load_n(
				&kcov_shm->pc_ctx.childop_local_pc_calls[op],
				__ATOMIC_RELAXED);
			unsigned long rc = __atomic_load_n(
				&kcov_shm->pc_ctx.childop_remote_pc_calls[op],
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
					&kcov_shm->pc_ctx.childop_local_pc_calls[op_id],
					__ATOMIC_RELAXED);
				unsigned long lec = __atomic_load_n(
					&kcov_shm->pc_ctx.childop_local_pc_edge_calls[op_id],
					__ATOMIC_RELAXED);
				unsigned long len_ = __atomic_load_n(
					&kcov_shm->pc_ctx.childop_local_pc_edge_count[op_id],
					__ATOMIC_RELAXED);
				unsigned long rc = __atomic_load_n(
					&kcov_shm->pc_ctx.childop_remote_pc_calls[op_id],
					__ATOMIC_RELAXED);
				unsigned long rec = __atomic_load_n(
					&kcov_shm->pc_ctx.childop_remote_pc_edge_calls[op_id],
					__ATOMIC_RELAXED);
				unsigned long ren = __atomic_load_n(
					&kcov_shm->pc_ctx.childop_remote_pc_edge_count[op_id],
					__ATOMIC_RELAXED);

				snprintf(opname, sizeof(opname), "%s",
					 alt_op_name((enum child_op_type)op_id));
				output(0, "  %-24s %10lu %10lu %10lu %10lu %10lu %10lu\n",
				       opname, lc, lec, len_, rc, rec, ren);
			}
		}
}

static void dump_stats_render_kcov_remote_edge_producers(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

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
				&kcov_shm->pc_ctx.remote_pc_edge_count[i],
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
				&kcov_shm->pc_ctx.childop_remote_pc_edge_count[op],
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
				&kcov_shm->pc_ctx.local_pc_calls[nr],
				__ATOMIC_RELAXED);
			unsigned long lec = __atomic_load_n(
				&kcov_shm->pc_ctx.local_pc_edge_calls[nr],
				__ATOMIC_RELAXED);
			unsigned long len_ = __atomic_load_n(
				&kcov_shm->pc_ctx.local_pc_edge_count[nr],
				__ATOMIC_RELAXED);
			unsigned long rc = __atomic_load_n(
				&kcov_shm->pc_ctx.remote_pc_calls[nr],
				__ATOMIC_RELAXED);
			unsigned long rec = __atomic_load_n(
				&kcov_shm->pc_ctx.remote_pc_edge_calls[nr],
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
				&kcov_shm->pc_ctx.childop_local_pc_calls[op_id],
				__ATOMIC_RELAXED);
			unsigned long lec = __atomic_load_n(
				&kcov_shm->pc_ctx.childop_local_pc_edge_calls[op_id],
				__ATOMIC_RELAXED);
			unsigned long len_ = __atomic_load_n(
				&kcov_shm->pc_ctx.childop_local_pc_edge_count[op_id],
				__ATOMIC_RELAXED);
			unsigned long rc = __atomic_load_n(
				&kcov_shm->pc_ctx.childop_remote_pc_calls[op_id],
				__ATOMIC_RELAXED);
			unsigned long rec = __atomic_load_n(
				&kcov_shm->pc_ctx.childop_remote_pc_edge_calls[op_id],
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

static void dump_stats_render_kcov_per_syscall_last_edge_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int ro_top_nr[10];
		unsigned long ro_top_rate[10];
		unsigned int ro_top_count = 0;

		memset(ro_top_rate, 0, sizeof(ro_top_rate));

		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long lec = __atomic_load_n(
				&kcov_shm->pc_ctx.local_pc_edge_calls[i],
				__ATOMIC_RELAXED);
			unsigned long rec = __atomic_load_n(
				&kcov_shm->pc_ctx.remote_pc_edge_calls[i],
				__ATOMIC_RELAXED);
			unsigned long ren, rate;

			if (lec != 0 || rec == 0)
				continue;
			ren = __atomic_load_n(
				&kcov_shm->pc_ctx.remote_pc_edge_count[i],
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
					&kcov_shm->pc_ctx.local_pc_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long rc = __atomic_load_n(
					&kcov_shm->pc_ctx.remote_pc_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long rec = __atomic_load_n(
					&kcov_shm->pc_ctx.remote_pc_edge_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long ren = __atomic_load_n(
					&kcov_shm->pc_ctx.remote_pc_edge_count[nr],
					__ATOMIC_RELAXED);

				output(0, "  %-24s %10lu %10lu %10lu %10lu %4lu.%03lu\n",
				       name, lc, rc, rec, ren,
				       milli / 1000, milli % 1000);
			}
		}
}

static void dump_stats_render_kcov_per_syscall_last_efault_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int re_top_nr[10];
		unsigned long re_top_gap[10];
		unsigned int re_top_count = 0;

		memset(re_top_gap, 0, sizeof(re_top_gap));

		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long req = __atomic_load_n(
				&kcov_shm->remote_enable.remote_enable_requested[i],
				__ATOMIC_RELAXED);
			unsigned long succ;
			unsigned long gap;

			if (req == 0)
				continue;
			succ = __atomic_load_n(
				&kcov_shm->remote_enable.remote_enable_succeeded[i],
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
					&kcov_shm->remote_enable.remote_enable_requested[nr],
					__ATOMIC_RELAXED);
				unsigned long succ = __atomic_load_n(
					&kcov_shm->remote_enable.remote_enable_succeeded[nr],
					__ATOMIC_RELAXED);
				unsigned long fail = __atomic_load_n(
					&kcov_shm->remote_enable.remote_enable_failed[nr],
					__ATOMIC_RELAXED);
				unsigned long fbl = __atomic_load_n(
					&kcov_shm->remote_enable.remote_fallback_to_local[nr],
					__ATOMIC_RELAXED);
				unsigned long gap = succ >= req ? 0 : req - succ;
				unsigned long milli = (gap * 1000UL) / req;

				output(0, "  %-24s %10lu %10lu %10lu %10lu %10lu %4lu.%03lu\n",
				       name, req, succ, fail, fbl, gap,
				       milli / 1000, milli % 1000);
			}
		}
}

static void dump_stats_render_kcov_per_syscall_local_pc_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int w_top_nr[10];
		unsigned long w_top_req[10];
		unsigned int w_top_count = 0;

		memset(w_top_req, 0, sizeof(w_top_req));

		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long req = __atomic_load_n(
				&kcov_shm->remote_enable.remote_enable_requested[i],
				__ATOMIC_RELAXED);
			unsigned long rec;

			if (req < REMOTE_WASTE_FLOOR)
				continue;
			rec = __atomic_load_n(
				&kcov_shm->pc_ctx.remote_pc_edge_calls[i],
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
					&kcov_shm->remote_enable.remote_enable_succeeded[nr],
					__ATOMIC_RELAXED);
				unsigned long fail = __atomic_load_n(
					&kcov_shm->remote_enable.remote_enable_failed[nr],
					__ATOMIC_RELAXED);
				unsigned long fbl = __atomic_load_n(
					&kcov_shm->remote_enable.remote_fallback_to_local[nr],
					__ATOMIC_RELAXED);
				unsigned long rc = __atomic_load_n(
					&kcov_shm->pc_ctx.remote_pc_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long ren = __atomic_load_n(
					&kcov_shm->pc_ctx.remote_pc_edge_count[nr],
					__ATOMIC_RELAXED);
				bool heavy = entry &&
					(entry->flags & KCOV_REMOTE_HEAVY);

				output(0, "  %-2s %-24s %10lu %10lu %10lu %10lu %10lu %10lu\n",
				       heavy ? "H" : "-", name,
				       req, succ, fail, fbl, rc, ren);
			}
		}
}
/* Render the shadow-measurement counter blocks that sit at the tail
 * of dump_stats_render_kcov_base_stats().  Each block surfaces the
 * would_fire / would_win pair for one shadow-only lane and, where
 * applicable, a per-mille ratio.  Split out so the base function no
 * longer carries fourteen shadow-only locals plus a hundred-and-fifty
 * lines of counter formatting; behaviour-neutral by construction --
 * every stat_row call, its gate, and its ordering is preserved. */
static void dump_stats_render_kcov_shadow_measurements(void)
{
	unsigned long kc_cmp_save_reject_nonconst      = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_nonconst,      __ATOMIC_RELAXED);
	unsigned long kc_cmp_nonconst_arg1_unique      = __atomic_load_n(&kcov_shm->cmp_nonconst_arg1_unique,           __ATOMIC_RELAXED);
	unsigned long kc_cmp_nonconst_arg2_unique      = __atomic_load_n(&kcov_shm->cmp_nonconst_arg2_unique,           __ATOMIC_RELAXED);
	unsigned long kc_cmp_nonconst_both_match       = __atomic_load_n(&kcov_shm->cmp_nonconst_both_match,            __ATOMIC_RELAXED);
	unsigned long kc_cmp_nonconst_would_attribute  = __atomic_load_n(&kcov_shm->cmp_nonconst_would_attribute,       __ATOMIC_RELAXED);
	unsigned long kc_cmp_nonconst_measured         = __atomic_load_n(&kcov_shm->cmp_nonconst_measured,              __ATOMIC_RELAXED);
	unsigned long kc_cmp_width_pin_total           = __atomic_load_n(&kcov_shm->cmp_width_pin_total,                __ATOMIC_RELAXED);
	unsigned long kc_cmp_width_pin_would_differ    = __atomic_load_n(&kcov_shm->cmp_width_pin_would_differ,         __ATOMIC_RELAXED);
	unsigned long kc_cmp_hyp_pow2_derive_would_fire = __atomic_load_n(&kcov_shm->cmp_hyp_pow2_derive_would_fire,    __ATOMIC_RELAXED);
	unsigned long kc_cmp_hyp_pow2_derive_would_win  = __atomic_load_n(&kcov_shm->cmp_hyp_pow2_derive_would_win,     __ATOMIC_RELAXED);
	unsigned long kc_cmp_hyp_bm_full_or_would_fire     = __atomic_load_n(&kcov_shm->cmp_hyp_bitmask_full_or_would_fire,        __ATOMIC_RELAXED);
	unsigned long kc_cmp_hyp_bm_full_or_would_win      = __atomic_load_n(&kcov_shm->cmp_hyp_bitmask_full_or_would_win,         __ATOMIC_RELAXED);
	unsigned long kc_cmp_hyp_bm_andnot_would_fire      = __atomic_load_n(&kcov_shm->cmp_hyp_bitmask_andnot_toggle_would_fire,  __ATOMIC_RELAXED);
	unsigned long kc_cmp_hyp_bm_andnot_would_win       = __atomic_load_n(&kcov_shm->cmp_hyp_bitmask_andnot_toggle_would_win,   __ATOMIC_RELAXED);

	/* Shadow measurement of the non-const relational drop-site.
	 * Counts records the CMP loop drops today into
	 * cmp_hints_save_reject_nonconst but that a future relational-
	 * attribution lane could plausibly act on.  would_attribute is
	 * the actionable population (exactly one operand uniquely ours,
	 * the other side not ours at all).
	 *
	 * Two ratios are emitted because the denominators mean different
	 * things and neither can be recovered from the other post-hoc:
	 *
	 *   per_mille_dropped  -- share of ALL non-const drops that would
	 *     be actionable.  Denominator (reject_nonconst) includes every
	 *     early-out where rec_num_args==0 and the measurement never
	 *     ran (child==NULL, redqueen disabled, in_reexec, dispatch_
	 *     args invalid, reexec_pending full at entry).  Reads as
	 *     "of the whole drop stream, what fraction is reachable" --
	 *     useful for sizing the drop tax, understates lane hit-rate.
	 *
	 *   per_mille_measured -- share of ADDRESSABLE non-const records
	 *     (those where the shadow loop actually ran) that would be
	 *     actionable.  This is the honest lane hit-rate on the
	 *     population a relational lane could conceivably see. */
	if (kc_cmp_nonconst_arg1_unique > 0)
		stat_row("kcov_coverage", "cmp_nonconst_arg1_unique", kc_cmp_nonconst_arg1_unique);
	if (kc_cmp_nonconst_arg2_unique > 0)
		stat_row("kcov_coverage", "cmp_nonconst_arg2_unique", kc_cmp_nonconst_arg2_unique);
	if (kc_cmp_nonconst_both_match > 0)
		stat_row("kcov_coverage", "cmp_nonconst_both_match", kc_cmp_nonconst_both_match);
	if (kc_cmp_nonconst_would_attribute > 0)
		stat_row("kcov_coverage", "cmp_nonconst_would_attribute", kc_cmp_nonconst_would_attribute);
	if (kc_cmp_nonconst_measured > 0)
		stat_row("kcov_coverage", "cmp_nonconst_measured", kc_cmp_nonconst_measured);
	if (kc_cmp_save_reject_nonconst > 0) {
		unsigned long ratio_milli =
			(kc_cmp_nonconst_would_attribute * 1000UL) /
			kc_cmp_save_reject_nonconst;
		stat_row("kcov_coverage", "cmp_nonconst_would_attribute_per_mille_dropped", ratio_milli);
	}
	if (kc_cmp_nonconst_measured > 0) {
		unsigned long ratio_milli =
			(kc_cmp_nonconst_would_attribute * 1000UL) /
			kc_cmp_nonconst_measured;
		stat_row("kcov_coverage", "cmp_nonconst_would_attribute_per_mille_measured", ratio_milli);
	}

	/* Shadow measurement of a high-bit-preserving replacement for the
	 * width-masked CMP RedQueen pin.  cmp_width_pin_total counts every
	 * unique width-match stamp; cmp_width_pin_would_differ counts the
	 * subset where the matched slot carries non-zero bits outside
	 * width_mask, so a syzkaller-style splice (orig high bits | arg1
	 * low bits) would produce a value different from today's whole-
	 * slot overwrite with arg1.  Ratio in per-mille sizes the headroom
	 * a preserving lever would open up; the live pin is unchanged. */
	if (kc_cmp_width_pin_total > 0)
		stat_row("kcov_coverage", "cmp_width_pin_total", kc_cmp_width_pin_total);
	if (kc_cmp_width_pin_would_differ > 0)
		stat_row("kcov_coverage", "cmp_width_pin_would_differ", kc_cmp_width_pin_would_differ);
	if (kc_cmp_width_pin_total > 0) {
		unsigned long ratio_milli =
			(kc_cmp_width_pin_would_differ * 1000UL) /
			kc_cmp_width_pin_total;
		stat_row("kcov_coverage", "cmp_width_pin_would_differ_per_mille", ratio_milli);
	}

	/* Shadow measurement of a POW2 / alignment probe class in the
	 * typed-hypothesis derive.  cmp_hyp_pow2_derive_would_fire counts
	 * every derive whose callsite is a size / offset-class argtype
	 * (ARG_RANGE / ARG_STRUCT_SIZE) AND whose picked exemplar sits at
	 * or near a power of two, so a pow2 / align probe class would be
	 * eligible to emit.  cmp_hyp_pow2_derive_would_win counts the
	 * subset where at least one candidate from the {C>>1, C, C<<1,
	 * round-to-512, round-to-4096, round-to-page-size} ladder differs
	 * from the value the live derive lane just emitted, so the class
	 * would have contributed a value the existing lanes did not.
	 * The live derive is byte-for-byte unchanged; the ratio in
	 * per-mille sizes the coverage headroom of promoting the class. */
	if (kc_cmp_hyp_pow2_derive_would_fire > 0)
		stat_row("kcov_coverage", "cmp_hyp_pow2_derive_would_fire", kc_cmp_hyp_pow2_derive_would_fire);
	if (kc_cmp_hyp_pow2_derive_would_win > 0)
		stat_row("kcov_coverage", "cmp_hyp_pow2_derive_would_win", kc_cmp_hyp_pow2_derive_would_win);
	if (kc_cmp_hyp_pow2_derive_would_fire > 0) {
		unsigned long ratio_milli =
			(kc_cmp_hyp_pow2_derive_would_win * 1000UL) /
			kc_cmp_hyp_pow2_derive_would_fire;
		stat_row("kcov_coverage", "cmp_hyp_pow2_derive_would_win_per_mille", ratio_milli);
	}

	/* Shadow measurement of BITMASK combination probe classes in the
	 * typed-hypothesis derive.  Extends the live single-bit lane at
	 * (nr, cmp_ip, width) with two combo probes:
	 *
	 *   cmp_hyp_bitmask_full_or_would_fire counts every BITMASK derive
	 *   whose accumulated mask has popcount >= 2 (single-bit lane
	 *   picks ONE bit per fire, so any (flags & A) && (flags & B) gate
	 *   is unreachable structurally); cmp_hyp_bitmask_full_or_would_win
	 *   counts the subset where the full OR differs from the single-
	 *   bit value the live lane just emitted -- i.e. the FULL_OR combo
	 *   would have contributed a value the single-bit lane did not.
	 *
	 *   cmp_hyp_bitmask_andnot_toggle_would_fire counts every BITMASK
	 *   derive where the complement of the observed-bits set inside
	 *   the operand width holds 1..8 bits -- a plausible disallowed-
	 *   bit mask for an `x & ~c` allow-mask check;
	 *   cmp_hyp_bitmask_andnot_toggle_would_win counts the subset
	 *   where at least one (mask | one-disallowed-bit) candidate
	 *   differs from the value the live lane emitted, so a live
	 *   toggle sweep would surface a value the single-bit lane did
	 *   not.  The live derive is byte-for-byte unchanged; ratios in
	 *   per-mille size the coverage headroom of promoting either
	 *   class. */
	if (kc_cmp_hyp_bm_full_or_would_fire > 0)
		stat_row("kcov_coverage", "cmp_hyp_bitmask_full_or_would_fire", kc_cmp_hyp_bm_full_or_would_fire);
	if (kc_cmp_hyp_bm_full_or_would_win > 0)
		stat_row("kcov_coverage", "cmp_hyp_bitmask_full_or_would_win", kc_cmp_hyp_bm_full_or_would_win);
	if (kc_cmp_hyp_bm_full_or_would_fire > 0) {
		unsigned long ratio_milli =
			(kc_cmp_hyp_bm_full_or_would_win * 1000UL) /
			kc_cmp_hyp_bm_full_or_would_fire;
		stat_row("kcov_coverage", "cmp_hyp_bitmask_full_or_would_win_per_mille", ratio_milli);
	}
	if (kc_cmp_hyp_bm_andnot_would_fire > 0)
		stat_row("kcov_coverage", "cmp_hyp_bitmask_andnot_toggle_would_fire", kc_cmp_hyp_bm_andnot_would_fire);
	if (kc_cmp_hyp_bm_andnot_would_win > 0)
		stat_row("kcov_coverage", "cmp_hyp_bitmask_andnot_toggle_would_win", kc_cmp_hyp_bm_andnot_would_win);
	if (kc_cmp_hyp_bm_andnot_would_fire > 0) {
		unsigned long ratio_milli =
			(kc_cmp_hyp_bm_andnot_would_win * 1000UL) /
			kc_cmp_hyp_bm_andnot_would_fire;
		stat_row("kcov_coverage", "cmp_hyp_bitmask_andnot_toggle_would_win_per_mille", ratio_milli);
	}

	/* Walk the shadow-arm promotion registry after the counter
	 * rows have been rendered.  Measure-only: for each registered
	 * arm whose baseline / would-win pair meets the promotion
	 * criterion, one surfacing line is emitted; no generation
	 * path is touched, no live_flag is flipped.  See
	 * cmp_hints/shadow_promote.c for the criterion and the
	 * pilot arm registrations. */
	shadow_promotion_evaluate();
}

static void dump_stats_render_kcov_base_stats(void)
{
	unsigned long kc_edges       = __atomic_load_n(&kcov_shm->coverage.edges_found,            __ATOMIC_RELAXED);
	/* See per-child kcov stats migration in stats_ring.h:
	 * total_pcs / total_calls / remote_calls read from
	 * parent_stats.  kcov_shm->coverage.total_calls is retained solely
	 * as the stamp source for last_edge_at[] / last_efault_at[];
	 * the kcov_shm total_pcs and remote_calls slots have no
	 * stamp-role consumer and are not bumped. */
	unsigned long kc_pcs         = parent_stats.total_pcs;
	unsigned long kc_calls       = parent_stats.total_calls;
	unsigned long kc_remote      = parent_stats.remote_calls;
	unsigned long kc_cmp_records = __atomic_load_n(&kcov_shm->cmp_records.cmp_records_collected,  __ATOMIC_RELAXED);
	unsigned long kc_cmp_trunc   = __atomic_load_n(&kcov_shm->cmp_records.cmp_trace_truncated,    __ATOMIC_RELAXED);
	unsigned long kc_dedup_overflow    = __atomic_load_n(&kcov_shm->dedup.dedup_probe_overflow,   __ATOMIC_RELAXED);
	unsigned long kc_dedup_max_probe   = __atomic_load_n(&kcov_shm->dedup.dedup_max_probe_seen,   __ATOMIC_RELAXED);
	unsigned long kc_cmp_bloom_skipped = __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_bloom_skipped, __ATOMIC_RELAXED);
	unsigned long kc_cmp_strip_skipped = __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_strip_skipped, __ATOMIC_RELAXED);
	unsigned long kc_cmp_unique  = __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_unique_inserts, __ATOMIC_RELAXED);
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
	dump_stats_render_kcov_transition_edges();
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

	dump_stats_render_kcov_shadow_measurements();
}

/* Find top 10 edge-producing syscalls via insertion sort, then a
 * skip-zero walk over the same table for the "Cold syscalls" tail --
 * both scans share the top_nr / top_edges / top_count / cold_count
 * locals declared here so the cold pass reads the running cold count
 * the top pass tallied without re-scanning. */
static void dump_stats_render_kcov_top_edges_and_cold(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int top_nr[10];
	unsigned long top_edges[10];
	unsigned int top_count = 0;
	unsigned int cold_count = 0;
	unsigned int i, j;

	memset(top_edges, 0, sizeof(top_edges));
	for (i = 0; i < nr_syscalls_to_scan; i++) {
		unsigned long edges = per_syscall_edges_total(i);

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
	dump_stats_render_kcov_per_syscall_edges_topn(nr_syscalls_to_scan, table);

	/* SHADOW-only Phase-1 per-syscall attribution-confidence dump.
	 * Silent by default (frontier_noise_sample==0); on any run with
	 * --frontier-noise-sample=N > 0 this renders a top-N with the
	 * clean numerator, the sampled-then-scaled global-delta noisy
	 * denominator, the resulting clean/est_noisy fraction, the
	 * local-only clean subset (clean - clean_remote), and the spare-
	 * cascade lane the frontier picker would consume. */
	dump_stats_render_kcov_per_syscall_noisy_topn(nr_syscalls_to_scan, table);

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
	dump_stats_render_kcov_per_syscall_calls_topn(nr_syscalls_to_scan, table);

	dump_stats_render_kcov_per_syscall_edge_calls_topn(nr_syscalls_to_scan, table);

	/* Sibling of "Top syscalls by recent edge growth": top-N by
	 * delta of per_syscall_cmp_inserts since the last dump_stats().
	 * A syscall whose CMP-insert rate is high while its edge-growth
	 * rate is flat is producing CMP signal that is not turning into
	 * coverage -- the CMP-rising-PC-flat plateau pattern. */
	dump_stats_render_kcov_per_syscall_cold_topn(nr_syscalls_to_scan, table);

	if (cold_count > 0) {
		unsigned int arch;

		output(0, "Cold syscalls (need better sanitise): %u\n", cold_count);
		/* Split by the per_syscall_edges[nr][arch] arch dim so an
		 * IA32-compat-only edge contribution is not silently folded
		 * into the 64-bit row.  Mirrors the biarch-aware iteration
		 * shape kcov_diag_emit_block uses (see stats/kcov_diag.c):
		 * iterate arch 0/1, label do32?"32":"64", skip zero rows.
		 * cold_count / kcov_syscall_is_cold stay per-nr -- the cold
		 * classification does not split by arch. */
		for (arch = 0; arch < 2; arch++) {
			bool do32 = (arch == 1);

			for (i = 0; i < nr_syscalls_to_scan; i++) {
				struct syscallentry *entry;
				unsigned long slot_edges;

				if (!kcov_syscall_is_cold(i))
					continue;

				slot_edges = __atomic_load_n(
					&kcov_shm->per_syscall.per_syscall_edges[i][arch],
					__ATOMIC_RELAXED);
				if (slot_edges == 0)
					continue;

				entry = table[i].entry;
				output(0, "  %-24s [arch=%s] (edges:%lu, last new @ call %lu)\n",
					entry ? entry->name : "???",
					do32 ? "32" : "64",
					slot_edges,
					kcov_shm->per_syscall.last_edge_at[i]);
			}
		}
	}
}

void __cold dump_stats_kcov_block(void)
{
	if (kcov_shm != NULL) {
		unsigned int nr_syscalls_to_scan;
		const struct syscalltable *table;

		dump_stats_render_kcov_base_stats();

		/* CMP-hint freshness / tier observability rollup.  See the
		 * counter-block comment in include/kcov.h next to
		 * cmp_hint_tier_recent_wins for the per-counter semantics.
		 * Gates on a non-zero summed value so a run that never
		 * exercised the consumer path stays silent in stats.  Per-
		 * bucket detail rendered as a compact tier_age_<n> row
		 * family so a downstream stats consumer can index by
		 * bucket without parsing a sub-structured value. */
		dump_stats_render_kcov_cmp_hint_tier();

		dump_stats_render_kcov_warm_known_hits();

		dump_stats_render_kcov_reexec();

		dump_stats_render_kcov_ring_replay();

		dump_stats_render_kcov_cmp_field_consumer();

		dump_stats_render_kcov_exit_edge_delta();

		dump_stats_render_kcov_exit_edge_totals();

		/* Setup shared by the top-edges / cold pass below and all
		 * top-N helpers that follow.  The biarch table choice + the
		 * MAX_NR_SYSCALL clamp are the same for every downstream
		 * scan so they're computed here once. */
		nr_syscalls_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
		if (nr_syscalls_to_scan > MAX_NR_SYSCALL)
			nr_syscalls_to_scan = MAX_NR_SYSCALL;
		table = biarch ? syscalls_64bit : syscalls;

		dump_stats_render_kcov_top_edges_and_cold(nr_syscalls_to_scan, table);

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
		dump_stats_render_kcov_per_syscall_yield_topn(nr_syscalls_to_scan, table);

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
		dump_stats_render_kcov_kcov_dispatch_stats();

		/* per-syscall +
		 * per-childop local-vs-remote PC yield, top-N by combined
		 * call count.  Lets the operator see whether a static
		 * remote-sampling policy is spending samples on a mode that
		 * yields no fresh edges -- the global remote_calls counter
		 * above can't answer that question.  Silent when no slot has
		 * any combined activity; columns: calls / edge-calls /
		 * raw-edge-count per mode. */
		dump_stats_render_kcov_per_syscall_dedup_topn(nr_syscalls_to_scan, table);
		dump_stats_render_kcov_kcov_probe_costs();

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
		dump_stats_render_kcov_remote_edge_producers(nr_syscalls_to_scan, table);

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
		dump_stats_render_kcov_per_syscall_last_edge_topn(nr_syscalls_to_scan, table);

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
		dump_stats_render_kcov_per_syscall_last_efault_topn(nr_syscalls_to_scan, table);

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
		dump_stats_render_kcov_per_syscall_local_pc_topn(nr_syscalls_to_scan, table);

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
