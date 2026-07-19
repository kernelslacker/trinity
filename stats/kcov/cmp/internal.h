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

void kcov_cmp_hyp_saturation_block_render(long elapsed);
void kcov_cmp_render_hyp_shadow_per_kind_census(void);
void kcov_cmp_render_hyp_shadow_consumes_census(void);
void kcov_cmp_render_hyp_shadow_picker_census(void);
void kcov_cmp_render_hyp_shadow_state_transitions(void);
void kcov_cmp_render_hyp_shadow_outcome_partition(void);
void kcov_cmp_render_hyp_shadow_stats_block(long elapsed);
void kcov_cmp_render_hyp_would_pick_block(long elapsed);
void kcov_cmp_render_hyp_would_promote_demote_block(long elapsed);
void kcov_cmp_render_hyp_live_inject_block(long elapsed);
void kcov_cmp_render_hyp_live_inject_reasons_block(long elapsed);
void kcov_cmp_render_hyp_boundary_scorecard_block(long elapsed);
void kcov_cmp_render_hyp_per_hypothesis_aggregates_block(long elapsed);
void kcov_cmp_render_hyp_score_bucket_block(long elapsed);
void kcov_cmp_render_hyp_probe_class_hist_block(long elapsed);

void kcov_cmp_render_childop_cmp_consume_shadow_block(long elapsed);

void kcov_cmp_render_ab_baseline_inject_denom(long elapsed,
					      unsigned long delta_cmp_inject_arm_a_baseline_fires, unsigned long cur_cmp_inject_arm_a_baseline_fires,
					      unsigned long delta_cmp_inject_arm_b_baseline_fires, unsigned long cur_cmp_inject_arm_b_baseline_fires,
					      unsigned long delta_cmp_inject_denom_diverged, unsigned long cur_cmp_inject_denom_diverged,
					      unsigned int cur_cmp_inject_arm_a_children,
					      unsigned int cur_cmp_inject_arm_b_children);
void kcov_cmp_render_handle_arg_op_prop_ring_cohort(long elapsed,
						    unsigned long delta_prop_ring_argop_arm_b_fires,
						    unsigned long cur_prop_ring_argop_arm_b_fires,
						    unsigned int cur_prop_ring_argop_arm_a_children,
						    unsigned int cur_prop_ring_argop_arm_b_children);
void kcov_cmp_render_frontier_cold_weight_blend_cohort(long elapsed,
						       unsigned long delta_frontier_blend_samples,
						       unsigned long cur_frontier_blend_samples,
						       unsigned int cur_frontier_blend_arm_a_children,
						       unsigned int cur_frontier_blend_arm_b_children);
void kcov_cmp_render_adaptive_remote_kcov_cohort(long elapsed,
						 unsigned long delta_remote_adaptive_samples,
						 unsigned long cur_remote_adaptive_samples,
						 unsigned int cur_remote_adaptive_arm_a_children,
						 unsigned int cur_remote_adaptive_arm_b_children,
						 unsigned long cur_remote_adaptive_would_demote,
						 unsigned long cur_remote_adaptive_would_promote,
						 unsigned long cur_remote_adaptive_would_force,
						 unsigned long cur_remote_adaptive_would_gate_promote,
						 unsigned long cur_remote_adaptive_agree);
void kcov_cmp_render_per_arg_ownership_sidecar(unsigned long cur_blanket_address_scrub_slots_walked,
					       unsigned long cur_arg_meta_addr_with_meta,
					       unsigned long cur_arg_meta_addr_without_meta,
					       unsigned long cur_arg_meta_argtype_stale,
					       unsigned long cur_arg_meta_scrub_would_destroy_in,
					       unsigned long cur_arg_meta_scrub_would_preserve_out);
void kcov_cmp_render_structure_aware_picker_cohort(long elapsed,
						   unsigned long delta_mut_structured_shadow_divergences,
						   unsigned long cur_mut_structured_shadow_divergences,
						   unsigned long cur_mut_structured_shadow_samples,
						   unsigned int cur_mut_structured_arm_a_children,
						   unsigned int cur_mut_structured_arm_b_children);

void kcov_cmp_render_modes_block(void);
void kcov_cmp_render_diag_errnos_block(void);
void kcov_cmp_render_pc_diag_block(void);
