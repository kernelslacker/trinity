/*
 * Private declarations shared across stats/kcov/cmp/ render TUs.
 *
 * All prototypes here are called only from within the stats/kcov/cmp/ TUs;
 * the only public entry point is kcov_cmp_stats_periodic_dump(), which stays
 * declared in include/stats.h.  Keep new declarations local to this file
 * unless a non-KCOV-CMP stats file genuinely needs them.
 */

#pragma once

void kcov_cmp_rate_line(long elapsed, const char *name,
			unsigned long delta, unsigned long total);

void kcov_cmp_observability_block_render(long elapsed);
void kcov_cmp_render_wild_write_delta(long elapsed,
				      unsigned long delta_count_oob, unsigned long cur_count_oob,
				      unsigned long delta_canary_lock_post, unsigned long cur_canary_lock_post,
				      unsigned long delta_canary_pre, unsigned long cur_canary_pre,
				      unsigned long delta_canary_post, unsigned long cur_canary_post);

void kcov_redqueen_observability_block_render(long elapsed);
void kcov_cmp_render_reexec_skip_reason_breakdown(long elapsed,
						  unsigned long delta_reexec_gate_skip_in_reexec, unsigned long cur_reexec_gate_skip_in_reexec,
						  unsigned long delta_reexec_gate_skip_disabled, unsigned long cur_reexec_gate_skip_disabled,
						  unsigned long delta_reexec_gate_skip_mode, unsigned long cur_reexec_gate_skip_mode,
						  unsigned long delta_reexec_gate_skip_chain_mid, unsigned long cur_reexec_gate_skip_chain_mid,
						  unsigned long delta_reexec_gate_skip_no_new_cmp, unsigned long cur_reexec_gate_skip_no_new_cmp,
						  unsigned long delta_reexec_gate_skip_no_pending, unsigned long cur_reexec_gate_skip_no_pending,
						  unsigned long delta_reexec_gate_skip_rate, unsigned long cur_reexec_gate_skip_rate,
						  unsigned long delta_reexec_gate_pass, unsigned long cur_reexec_gate_pass);

void kcov_cmp_sum_hyp_counters_per_syscall(unsigned int nr,
					   uint64_t *pc_wins,
					   uint64_t *consumed,
					   uint64_t *misses);
void kcov_cmp_render_oldpool_per_syscall_topn(void);
void kcov_cmp_oldpool_vs_shadow_block_render(long elapsed);
void kcov_cmp_render_pc_win_conversion_split_block(long elapsed);
void kcov_cmp_render_per_entry_feedback_scoring(long elapsed,
						unsigned long delta_cmp_hints_consumed, unsigned long cur_cmp_hints_consumed,
						unsigned long delta_cmp_hint_wins, unsigned long cur_cmp_hint_wins,
						unsigned long delta_cmp_hint_misses, unsigned long cur_cmp_hint_misses,
						unsigned long delta_cmp_hint_cmp_novelty_wins, unsigned long cur_cmp_hint_cmp_novelty_wins,
						unsigned long delta_cmp_hint_stash_overflow, unsigned long cur_cmp_hint_stash_overflow,
						unsigned long delta_cmp_hint_credit_entry_evicted, unsigned long cur_cmp_hint_credit_entry_evicted);
void kcov_cmp_render_recent_cmp_pool_tier(long elapsed,
					  unsigned long delta_cmp_recent_inserts, unsigned long cur_cmp_recent_inserts,
					  unsigned long delta_cmp_recent_evicts, unsigned long cur_cmp_recent_evicts,
					  unsigned long delta_cmp_recent_would_pick, unsigned long cur_cmp_recent_would_pick,
					  unsigned long delta_cmp_recent_would_miss, unsigned long cur_cmp_recent_would_miss,
					  unsigned long delta_cmp_recent_live_picks, unsigned long cur_cmp_recent_live_picks);
