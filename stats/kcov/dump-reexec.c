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

#include "dump-internal.h"

void dump_stats_render_kcov_cmp_hint_tier(void)
{
		unsigned long kc_tier_r_wins = __atomic_load_n(
			&kcov_shm->hint_tier.cmp_hint_tier_recent_wins,
			__ATOMIC_RELAXED);
		unsigned long kc_tier_r_misses = __atomic_load_n(
			&kcov_shm->hint_tier.cmp_hint_tier_recent_misses,
			__ATOMIC_RELAXED);
		unsigned long kc_tier_d_wins = __atomic_load_n(
			&kcov_shm->hint_tier.cmp_hint_tier_durable_wins,
			__ATOMIC_RELAXED);
		unsigned long kc_tier_d_misses = __atomic_load_n(
			&kcov_shm->hint_tier.cmp_hint_tier_durable_misses,
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
					__atomic_load_n(&kcov_shm->hint_tier.cmp_hint_durable_consumed_age[b],
							__ATOMIC_RELAXED);
				unsigned long v_wins =
					__atomic_load_n(&kcov_shm->hint_tier.cmp_hint_durable_age_wins[b],
							__ATOMIC_RELAXED);
				unsigned long v_misses =
					__atomic_load_n(&kcov_shm->hint_tier.cmp_hint_durable_age_misses[b],
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

void dump_stats_render_kcov_reexec(void)
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
		unsigned long rx_gate_skip_in_reexec = __atomic_load_n(&kcov_shm->reexec_gate.reexec_gate_skip_in_reexec, __ATOMIC_RELAXED);
		unsigned long rx_gate_skip_disabled = __atomic_load_n(&kcov_shm->reexec_gate.reexec_gate_skip_disabled, __ATOMIC_RELAXED);
		unsigned long rx_gate_skip_mode = __atomic_load_n(&kcov_shm->reexec_gate.reexec_gate_skip_mode, __ATOMIC_RELAXED);
		unsigned long rx_gate_skip_chain_mid = __atomic_load_n(&kcov_shm->reexec_gate.reexec_gate_skip_chain_mid, __ATOMIC_RELAXED);
		unsigned long rx_gate_skip_no_new_cmp = __atomic_load_n(&kcov_shm->reexec_gate.reexec_gate_skip_no_new_cmp, __ATOMIC_RELAXED);
		unsigned long rx_gate_skip_no_pending = __atomic_load_n(&kcov_shm->reexec_gate.reexec_gate_skip_no_pending, __ATOMIC_RELAXED);
		unsigned long rx_gate_skip_rate = __atomic_load_n(&kcov_shm->reexec_gate.reexec_gate_skip_rate, __ATOMIC_RELAXED);
		unsigned long rx_gate_pass = __atomic_load_n(&kcov_shm->reexec_gate.reexec_gate_pass, __ATOMIC_RELAXED);

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

void dump_stats_render_kcov_ring_replay(void)
{
		unsigned long fx_scanned = __atomic_load_n(&kcov_shm->cmp_field_attr.cmp_field_attribution_scanned, __ATOMIC_RELAXED);
		unsigned long fx_found = __atomic_load_n(&kcov_shm->cmp_field_attr.cmp_field_attribution_found, __ATOMIC_RELAXED);
		unsigned long fx_pool_full = __atomic_load_n(&kcov_shm->cmp_field_attr.cmp_field_attribution_pool_full, __ATOMIC_RELAXED);
		unsigned long fx_bad_ptr = __atomic_load_n(&kcov_shm->cmp_field_attr.cmp_field_attribution_arg_skipped_bad_ptr, __ATOMIC_RELAXED);
		unsigned long fx_short_alloc = __atomic_load_n(&kcov_shm->cmp_field_attr.cmp_field_attribution_arg_skipped_short_alloc, __ATOMIC_RELAXED);
		unsigned long fx_ts_bad_ptr = __atomic_load_n(&kcov_shm->cmp_field_attr.cmp_field_timespec_skipped_bad_ptr, __ATOMIC_RELAXED);

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

void dump_stats_render_kcov_cmp_field_consumer(void)
{
		unsigned long fc_would_pick = __atomic_load_n(&kcov_shm->field_consumer.cmp_field_consumer_would_pick, __ATOMIC_RELAXED);
		unsigned long fc_would_differs = __atomic_load_n(&kcov_shm->field_consumer_shadow.cmp_field_consumer_would_value_differs, __ATOMIC_RELAXED);
		unsigned long fc_would_miss = __atomic_load_n(&kcov_shm->field_consumer.cmp_field_consumer_would_miss, __ATOMIC_RELAXED);
		unsigned long fc_key_absent = __atomic_load_n(&kcov_shm->field_consumer.cmp_field_consumer_key_absent, __ATOMIC_RELAXED);
		unsigned long fc_pool_corrupt = __atomic_load_n(&kcov_shm->field_consumer.cmp_field_consumer_pool_corrupted, __ATOMIC_RELAXED);
		unsigned long fc_live_picks = __atomic_load_n(&kcov_shm->field_consumer.cmp_field_consumer_live_picks, __ATOMIC_RELAXED);
		unsigned long fc_g_variant = __atomic_load_n(&kcov_shm->field_consumer_guard.cmp_field_consumer_guard_variant_layout, __ATOMIC_RELAXED);
		unsigned long fc_g_bufdisc = __atomic_load_n(&kcov_shm->field_consumer_guard.cmp_field_consumer_guard_buffer_discrim, __ATOMIC_RELAXED);
		unsigned long fc_g_lenpair = __atomic_load_n(&kcov_shm->field_consumer_guard.cmp_field_consumer_guard_len_pair, __ATOMIC_RELAXED);
		unsigned long fc_g_nested = __atomic_load_n(&kcov_shm->field_consumer_guard.cmp_field_consumer_guard_nested_pointer, __ATOMIC_RELAXED);
		unsigned long fc_g_dep = __atomic_load_n(&kcov_shm->field_consumer_guard.cmp_field_consumer_guard_dependent, __ATOMIC_RELAXED);
		unsigned long fc_p_elig = __atomic_load_n(&kcov_shm->field_consumer_prove.cmp_field_consumer_prove_eligible, __ATOMIC_RELAXED);
		unsigned long fc_p_edges = __atomic_load_n(&kcov_shm->field_consumer_prove.cmp_field_consumer_prove_edges_at_pick, __ATOMIC_RELAXED);
		unsigned long fc_p_cmps = __atomic_load_n(&kcov_shm->field_consumer_prove.cmp_field_consumer_prove_cmp_records_at_pick, __ATOMIC_RELAXED);
		unsigned long fc_p_einval = __atomic_load_n(&kcov_shm->field_consumer_prove.cmp_field_consumer_prove_einval_at_pick, __ATOMIC_RELAXED);

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
