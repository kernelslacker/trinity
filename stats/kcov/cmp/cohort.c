/*
 * Cross-subsystem A/B and sidecar periodic reporting.
 *
 * Owns the experiment/cohort renderers that share the "population-
 * normalised delta with per-arm cohort split" row shape: A/B baseline
 * inject denom, handle_arg_op prop_ring, frontier cold-weight blend,
 * adaptive remote-KCOV, per-arg ownership sidecar, and structure-aware
 * picker cohort.  Grouping them here makes the cross-subsystem
 * dependencies obvious and keeps the shared cohort/sidecar row shape
 * out of the core KCOV base render code.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <sys/utsname.h>
#include <stdio.h>
#include "arch.h"
#include "cmp_hints.h"
#include "kcov.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "trinity.h"
#include "utils.h"

#include "stats/kcov/cmp/internal.h"

void kcov_cmp_render_ab_baseline_inject_denom(long elapsed,
						     unsigned long delta_cmp_inject_arm_a_baseline_fires, unsigned long cur_cmp_inject_arm_a_baseline_fires,
						     unsigned long delta_cmp_inject_arm_b_baseline_fires, unsigned long cur_cmp_inject_arm_b_baseline_fires,
						     unsigned long delta_cmp_inject_denom_diverged, unsigned long cur_cmp_inject_denom_diverged,
						     unsigned int cur_cmp_inject_arm_a_children,
						     unsigned int cur_cmp_inject_arm_b_children)
{
	/* A/B baseline inject denom (Arm A = 16, Arm B = 12).  Print
	 * the realised cohort split + per-arm baseline-fire deltas +
	 * the per-call divergence count so the operator can size the
	 * A/B effect on PC-edge yield against population-normalised
	 * fire rates without recomputing from cmp_hint_callsite[]. */
	if (delta_cmp_inject_arm_a_baseline_fires) {
		unsigned long rate_milli = (delta_cmp_inject_arm_a_baseline_fires * 1000UL) / (unsigned long)elapsed;
		stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, children %u)\n",
				"cmp_inject_arm_a_baseline_fires",
				delta_cmp_inject_arm_a_baseline_fires,
				rate_milli / 1000, rate_milli % 1000,
				cur_cmp_inject_arm_a_baseline_fires,
				cur_cmp_inject_arm_a_children);
	}
	if (delta_cmp_inject_arm_b_baseline_fires) {
		unsigned long rate_milli = (delta_cmp_inject_arm_b_baseline_fires * 1000UL) / (unsigned long)elapsed;
		stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, children %u)\n",
				"cmp_inject_arm_b_baseline_fires",
				delta_cmp_inject_arm_b_baseline_fires,
				rate_milli / 1000, rate_milli % 1000,
				cur_cmp_inject_arm_b_baseline_fires,
				cur_cmp_inject_arm_b_children);
	}
	kcov_cmp_rate_line(elapsed, "cmp_inject_denom_diverged", delta_cmp_inject_denom_diverged, cur_cmp_inject_denom_diverged);
}
void kcov_cmp_render_handle_arg_op_prop_ring_cohort(long elapsed,
							   unsigned long delta_prop_ring_argop_arm_b_fires,
							   unsigned long cur_prop_ring_argop_arm_b_fires,
							   unsigned int cur_prop_ring_argop_arm_a_children,
							   unsigned int cur_prop_ring_argop_arm_b_children)
{
	/* A/B handle_arg_op prop_ring cohort (Arm A = no pull, Arm B =
	 * low-prob pull).  Print the realised cohort split + the Arm B
	 * fire delta so the operator can size the per-row contribution
	 * to propagation_injected against the population-normalised fire
	 * rate.  Arm A has no symmetric fire counter by design (control
	 * arm skips the pull entirely). */
	if (delta_prop_ring_argop_arm_b_fires) {
		unsigned long rate_milli = (delta_prop_ring_argop_arm_b_fires * 1000UL) / (unsigned long)elapsed;
		stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, children a=%u b=%u)\n",
				"prop_ring_argop_arm_b_fires",
				delta_prop_ring_argop_arm_b_fires,
				rate_milli / 1000, rate_milli % 1000,
				cur_prop_ring_argop_arm_b_fires,
				cur_prop_ring_argop_arm_a_children,
				cur_prop_ring_argop_arm_b_children);
	}
}
void kcov_cmp_render_frontier_cold_weight_blend_cohort(long elapsed,
							      unsigned long delta_frontier_blend_samples,
							      unsigned long cur_frontier_blend_samples,
							      unsigned int cur_frontier_blend_arm_a_children,
							      unsigned int cur_frontier_blend_arm_b_children)
{
	/* frontier_cold_weight blend A/B cohort (Arm A = return historical
	 * OLD weight, Arm B = promote blended weight including the
	 * transition term to the picker).  Both arms fire the would-be
	 * divergence sampler frontier_blend_samples in lock-step, so the
	 * delta gate uses that fire counter and the row prints the
	 * realised cohort split as the denominator the operator
	 * normalises the live Arm B promotion against.  Neither arm has
	 * a per-arm fire counter by design -- the blend logic itself is
	 * untouched. */
	if (delta_frontier_blend_samples) {
		unsigned long rate_milli = (delta_frontier_blend_samples * 1000UL) / (unsigned long)elapsed;
		stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, children a=%u b=%u)\n",
				"frontier_blend_samples",
				delta_frontier_blend_samples,
				rate_milli / 1000, rate_milli % 1000,
				cur_frontier_blend_samples,
				cur_frontier_blend_arm_a_children,
				cur_frontier_blend_arm_b_children);
	}
}
void kcov_cmp_render_adaptive_remote_kcov_cohort(long elapsed,
							unsigned long delta_remote_adaptive_samples,
							unsigned long cur_remote_adaptive_samples,
							unsigned int cur_remote_adaptive_arm_a_children,
							unsigned int cur_remote_adaptive_arm_b_children,
							unsigned long cur_remote_adaptive_would_demote,
							unsigned long cur_remote_adaptive_would_promote,
							unsigned long cur_remote_adaptive_would_force,
							unsigned long cur_remote_adaptive_would_gate_promote,
							unsigned long cur_remote_adaptive_agree)
{
	/* Adaptive remote-KCOV mode A/B cohort (Arm A = static remote-
	 * mode policy / byte-identical to pre-row baseline, Arm B = the
	 * adaptive demote/promote disposition from
	 * remote_adaptive_decide() substituted as the live remote_mode).
	 * Both arms feed the would-be disposition counters in lock-
	 * step, so the headline samples row uses the realised cohort
	 * split as the denominator the operator normalises the Arm-B-
	 * only live divergence against.  The three sub-rows print
	 * unconditionally inside the gate so the breakdown is visible
	 * even on windows where one disposition is zero (the absence
	 * itself is the diagnostic signal). */
	if (delta_remote_adaptive_samples) {
		unsigned long rate_milli = (delta_remote_adaptive_samples * 1000UL) / (unsigned long)elapsed;
		stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, children a=%u b=%u)\n",
				"remote_adaptive_samples",
				delta_remote_adaptive_samples,
				rate_milli / 1000, rate_milli % 1000,
				cur_remote_adaptive_samples,
				cur_remote_adaptive_arm_a_children,
				cur_remote_adaptive_arm_b_children);
		stats_log_write("  %-32s total %lu\n",
				"remote_adaptive_would_demote",
				cur_remote_adaptive_would_demote);
		stats_log_write("  %-32s total %lu\n",
				"remote_adaptive_would_promote",
				cur_remote_adaptive_would_promote);
		stats_log_write("  %-32s total %lu\n",
				"remote_adaptive_would_force",
				cur_remote_adaptive_would_force);
		stats_log_write("  %-32s total %lu\n",
				"remote_adaptive_would_gate_promote",
				cur_remote_adaptive_would_gate_promote);
		stats_log_write("  %-32s total %lu\n",
				"remote_adaptive_agree",
				cur_remote_adaptive_agree);
	}
}
void kcov_cmp_render_per_arg_ownership_sidecar(unsigned long cur_blanket_address_scrub_slots_walked,
						      unsigned long cur_arg_meta_addr_with_meta,
						      unsigned long cur_arg_meta_addr_without_meta,
						      unsigned long cur_arg_meta_argtype_stale,
						      unsigned long cur_arg_meta_scrub_would_destroy_in,
						      unsigned long cur_arg_meta_scrub_would_preserve_out)
{
	/* SHADOW per-arg ownership-metadata sidecar + blanket-scrub
	 * contradiction census.  Telemetry only -- the arg_meta_init
	 * seed pass and blanket_address_scrub walk are byte-unchanged;
	 * no live decision reads dir/owner/flags.  Cumulative totals
	 * (no per-window delta) match the remote_adaptive_would_*
	 * neighbours above: the shadow PROOF here is the ratio between
	 * the with_meta / without_meta rows and the destroy_in /
	 * preserve_out skew the operator is sizing future metadata-
	 * aware scrub coverage against.  Unconditional render so the
	 * baseline (all zero until per-generator coverage populates
	 * dir/owner) is itself visible. */
	stats_log_write("  %-32s total %lu\n",
			"blanket_address_scrub_slots_walked",
			cur_blanket_address_scrub_slots_walked);
	stats_log_write("  %-32s total %lu\n",
			"arg_meta_addr_with_meta",
			cur_arg_meta_addr_with_meta);
	stats_log_write("  %-32s total %lu\n",
			"arg_meta_addr_without_meta",
			cur_arg_meta_addr_without_meta);
	stats_log_write("  %-32s total %lu\n",
			"arg_meta_argtype_stale",
			cur_arg_meta_argtype_stale);
	stats_log_write("  %-32s total %lu\n",
			"arg_meta_scrub_would_destroy_in",
			cur_arg_meta_scrub_would_destroy_in);
	stats_log_write("  %-32s total %lu\n",
			"arg_meta_scrub_would_preserve_out",
			cur_arg_meta_scrub_would_preserve_out);
}
void kcov_cmp_render_structure_aware_picker_cohort(long elapsed,
							  unsigned long delta_mut_structured_shadow_divergences,
							  unsigned long cur_mut_structured_shadow_divergences,
							  unsigned long cur_mut_structured_shadow_samples,
							  unsigned int cur_mut_structured_arm_a_children,
							  unsigned int cur_mut_structured_arm_b_children)
{
	/* SHADOW structure-aware picker A/B cohort (Arm A = no shadow
	 * draw / RNG byte-identical to pre-shadow control, Arm B =
	 * doubled-pool shadow draw on structured-eligible slots).  Print
	 * the Arm B divergence delta paired with the cumulative sample
	 * base and the realised cohort split so the operator can size
	 * the shadow's per-window steer-rate against the population-
	 * normalised denominator.  Arm A has no symmetric divergence
	 * counter by design (control arm skips the shadow draw entirely);
	 * samples and divergences are both Arm-B-only accumulators. */
	if (delta_mut_structured_shadow_divergences) {
		unsigned long rate_milli = (delta_mut_structured_shadow_divergences * 1000UL) / (unsigned long)elapsed;
		stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, samples %lu, children a=%u b=%u)\n",
				"mut_structured_shadow_divergences",
				delta_mut_structured_shadow_divergences,
				rate_milli / 1000, rate_milli % 1000,
				cur_mut_structured_shadow_divergences,
				cur_mut_structured_shadow_samples,
				cur_mut_structured_arm_a_children,
				cur_mut_structured_arm_b_children);
	}
}
