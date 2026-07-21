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

/* SHADOW-ONLY saturation-cooldown counters.  Gated by
 * --frontier-saturation-cooldown != off; zero on default-off runs
 * so the rows stay suppressed by the if-non-zero guard.  Read the
 * (would_skip / candidates) ratio for the spare-lane catch rate and
 * the per-syscall frontier_satcool_would_skip_per_syscall[] top-N
 * (rendered by dump_satcool_would_skip_per_syscall_top() below) to
 * confirm the demote mass concentrates on syncfs / sendfile /
 * semget / writev and is ~0 on removexattrat / futex /
 * io_uring_setup / bpf before tuning C_min or wiring the COMBINED
 * reject. */
static void dump_stats_render_frontier_satcool(void)
{
	if (shm->stats.frontier.saturation.satcool_candidates)
		stat_row("strategy", "frontier_satcool_candidates",
			 shm->stats.frontier.saturation.satcool_candidates);
	if (shm->stats.frontier.saturation.satcool_would_skip)
		stat_row("strategy", "frontier_satcool_would_skip",
			 shm->stats.frontier.saturation.satcool_would_skip);
	if (shm->stats.frontier.saturation.satcool_spared_arggen)
		stat_row("strategy", "frontier_satcool_spared_arggen",
			 shm->stats.frontier.saturation.satcool_spared_arggen);
	if (shm->stats.frontier.saturation.satcool_spared_objproducer)
		stat_row("strategy", "frontier_satcool_spared_objproducer",
			 shm->stats.frontier.saturation.satcool_spared_objproducer);
	dump_satcool_would_skip_per_syscall_top();
}

/* SHADOW-ONLY floored-barren sub-floor demote counters.  Gated by
 * --frontier-barren-demote != off; zero on default-off runs so the
 * rows stay suppressed by the if-non-zero guard.  Read the
 * (would_skip / candidates) ratio for the vetted-predicate demote
 * catch rate and the per-syscall frontier_barren_would_skip_per_
 * syscall[] top-N (rendered by dump_barren_would_skip_per_syscall_
 * top() below) to confirm the demote mass concentrates on the pure
 * zero-arg getter cohort and is ~0 on the object-producer / state-
 * mutator / heuristic-arm-spike sets the vetted skeleton excludes,
 * before considering the combined sub-floor ramp. */
static void dump_stats_render_frontier_barren(void)
{
	if (shm->stats.frontier.saturation.barren_candidates)
		stat_row("strategy", "frontier_barren_candidates",
			 shm->stats.frontier.saturation.barren_candidates);
	if (shm->stats.frontier.saturation.barren_would_skip)
		stat_row("strategy", "frontier_barren_would_skip",
			 shm->stats.frontier.saturation.barren_would_skip);
	dump_barren_would_skip_per_syscall_top();
}

/* SHADOW-ONLY cmp-frontier picker-arm counters.  Gated by
 * --cmp-frontier != off; zero on default-off runs so the rows stay
 * suppressed by the if-non-zero guard.  Read the
 * (would_route / samples) ratio for the projected route volume the
 * shadow arm would produce, and (live_routes / would_route) for the
 * subset actually routed once COMBINED replaces the accept weight,
 * before flipping shadow-only -> combined. */
static void dump_stats_render_frontier_cmp(void)
{
	if (shm->stats.cmp_frontier.samples)
		stat_row("strategy", "cmp_frontier_samples",
			 shm->stats.cmp_frontier.samples);
	if (shm->stats.cmp_frontier.would_route)
		stat_row("strategy", "cmp_frontier_would_route",
			 shm->stats.cmp_frontier.would_route);
	if (shm->stats.cmp_frontier.live_routes)
		stat_row("strategy", "cmp_frontier_live_routes",
			 shm->stats.cmp_frontier.live_routes);
}

/* SHADOW-ONLY LIVE-regime cooldown discriminator (gated by
 * --frontier-live-cooldown-mode != off).  Sibling block to the
 * undiscriminated frontier_live_cooldown_candidates / frontier_
 * live_would_skip rows above; this row projects the DISCRIMINATED
 * LIVE-regime demote mass after the spare lanes peel productive
 * syscalls out of the cool set.  Compare (live_cool_would_skip /
 * live_would_skip) for the over-cool fraction the discriminator
 * removes.  The low live floor (FRONTIER_LIVE_COOL_CMIN) is
 * emitted alongside so the operator can interpret the candidate
 * count without consulting the source, matching the
 * frontier_live_miss_cooldown_threshold row above. */
static void dump_stats_render_frontier_live_cool(void)
{
	if (shm->stats.frontier.discriminator.live_cool_candidates)
		stat_row("strategy", "frontier_live_cool_candidates",
			 shm->stats.frontier.discriminator.live_cool_candidates);
	if (shm->stats.frontier.discriminator.live_cool_would_skip)
		stat_row("strategy", "frontier_live_cool_would_skip",
			 shm->stats.frontier.discriminator.live_cool_would_skip);
	if (shm->stats.frontier.discriminator.live_cool_spared_windowed)
		stat_row("strategy", "frontier_live_cool_spared_windowed",
			 shm->stats.frontier.discriminator.live_cool_spared_windowed);
	if (shm->stats.frontier.discriminator.live_cool_spared_arggen)
		stat_row("strategy", "frontier_live_cool_spared_arggen",
			 shm->stats.frontier.discriminator.live_cool_spared_arggen);
	if (shm->stats.frontier.discriminator.live_cool_spared_objproducer)
		stat_row("strategy", "frontier_live_cool_spared_objproducer",
			 shm->stats.frontier.discriminator.live_cool_spared_objproducer);
	/* Threshold companion to the scalar rows above.  Gated on the
	 * discriminator mode rather than emitted unconditionally so a
	 * default-off run does not grow a new stats row (the cmin
	 * threshold is meaningful only when the discriminator is
	 * actually evaluating); the sibling dump_live_cool_per_syscall_
	 * top calls below already mode-OFF-early-return for the same
	 * default-identity contract.  Sibling rows like frontier_live_
	 * miss_cooldown_threshold above stay unconditional because
	 * their counters predate this discriminator's mode flag. */
	if (__atomic_load_n(&frontier_live_cooldown_mode,
			    __ATOMIC_RELAXED) !=
	    FRONTIER_LIVE_COOLDOWN_MODE_OFF)
		stat_row("strategy", "frontier_live_cool_cmin",
			 FRONTIER_LIVE_COOL_CMIN);
	dump_live_cool_per_syscall_top(
		shm->stats.frontier.discriminator.live_cool_would_skip_per_syscall,
		"frontier_live_cool_would_skip");
	dump_live_cool_per_syscall_top(
		shm->stats.frontier.discriminator.live_cool_would_spare_per_syscall,
		"frontier_live_cool_would_spare");
}

/* SHADOW-ONLY Path-A "regular_suppressed" context-axis projection.
 * Gated by --context-pool != off; zero on default-off runs so the
 * rows stay suppressed by the if-non-zero guard.  Read the
 * (would_skip / candidates) ratio for the projected regular-pool
 * pick share a live Path-A deactivation would reclaim; the spared_*
 * triple partitions the shared spare-lane cascade so a syscall
 * spared for windowed edges / arggen progress / objproducer status
 * is not mis-attributed to the would_skip pool.  The per-syscall
 * top-N (rendered by dump_context_regular_suppressed_per_syscall_
 * top() below) is the headline SHADOW_ONLY diagnostic: the demote
 * mass MUST concentrate on the measured EPERM hogs (fchown / chown
 * / lchown / fchownat + the cred family as seen at uid 1026) and
 * stay near zero on syscalls with unprivileged regular value before
 * tuning CMIN / EPERM_PCT or wiring the COMBINED live suppression.
 * The classifier thresholds are emitted alongside so the operator
 * can interpret the candidate count without consulting the source,
 * matching the frontier_live_cool_cmin row above. */
static void dump_stats_render_context_regular_suppressed(void)
{
	if (shm->stats.context_suppress.candidates)
		stat_row("strategy", "context_regular_suppressed_candidates",
			 shm->stats.context_suppress.candidates);
	if (shm->stats.context_suppress.would_skip)
		stat_row("strategy", "context_regular_suppressed_would_skip",
			 shm->stats.context_suppress.would_skip);
	if (shm->stats.context_suppress.spared_windowed)
		stat_row("strategy",
			 "context_regular_suppressed_spared_windowed",
			 shm->stats.context_suppress.spared_windowed);
	if (shm->stats.context_suppress.spared_arggen)
		stat_row("strategy",
			 "context_regular_suppressed_spared_arggen",
			 shm->stats.context_suppress.spared_arggen);
	if (shm->stats.context_suppress.spared_objproducer)
		stat_row("strategy",
			 "context_regular_suppressed_spared_objproducer",
			 shm->stats.context_suppress.spared_objproducer);
	if (__atomic_load_n(&context_pool_mode, __ATOMIC_RELAXED) !=
	    CONTEXT_POOL_MODE_OFF) {
		stat_row("strategy", "context_regular_suppressed_cmin",
			 CONTEXT_REGULAR_SUPPRESSED_CMIN);
		stat_row("strategy", "context_regular_suppressed_eperm_pct",
			 CONTEXT_REGULAR_SUPPRESSED_EPERM_PCT);
	}
	dump_context_regular_suppressed_per_syscall_top();
}

/* SHADOW-ONLY A/B scoring for the frontier-blend cold-weight
 * blend.  Emitted as a sibling block to the silent-decay shadow
 * counters above; the picker still consumes the OLD weight from
 * frontier_cold_weight() and these counters expose how often the
 * blended formula would have steered differently.  See the
 * struct-field comments in include/stats.h for semantics. */
static void dump_stats_render_frontier_blend(void)
{
	if (shm->stats.frontier.plateau.blend_samples) {
		stat_row("strategy", "frontier_blend_samples",
			 shm->stats.frontier.plateau.blend_samples);
		stat_row("strategy", "frontier_blend_new_lower",
			 shm->stats.frontier.plateau.blend_new_lower);
		stat_row("strategy", "frontier_blend_new_higher",
			 shm->stats.frontier.plateau.blend_new_higher);
		stat_row("strategy", "frontier_blend_new_equal",
			 shm->stats.frontier.plateau.blend_new_equal);
		stat_row("strategy", "frontier_blend_old_weight_sum",
			 shm->stats.frontier.plateau.blend_old_weight_sum);
		stat_row("strategy", "frontier_blend_new_weight_sum",
			 shm->stats.frontier.plateau.blend_new_weight_sum);
	}
}

/* Per-band shadow counters for --reach-band.  Sibling of the
 * frontier_blend_* block above.  Silent on default (OFF) runs --
 * the gate in frontier_cold_weight() early-outs before the bumps,
 * so the per-band picks array stays at zero and the if-guard
 * suppresses the whole block.  See the reach_band_* field-comment
 * block in include/stats.h for the SHADOW_ONLY vs COMBINED reading
 * of would_demote_mid / would_boost_high. */
static void dump_stats_render_reach_band(void)
{
	if (shm->stats.reach_band_picks_per_band[REACH_BAND_IDX_LOW] ||
	    shm->stats.reach_band_picks_per_band[REACH_BAND_IDX_MID] ||
	    shm->stats.reach_band_picks_per_band[REACH_BAND_IDX_HIGH]) {
		stat_row("strategy", "reach_band_picks_low",
			 shm->stats.reach_band_picks_per_band[REACH_BAND_IDX_LOW]);
		stat_row("strategy", "reach_band_picks_mid",
			 shm->stats.reach_band_picks_per_band[REACH_BAND_IDX_MID]);
		stat_row("strategy", "reach_band_picks_high",
			 shm->stats.reach_band_picks_per_band[REACH_BAND_IDX_HIGH]);
		stat_row("strategy", "reach_band_would_demote_mid",
			 shm->stats.reach_band_would_demote_mid);
		stat_row("strategy", "reach_band_would_boost_high",
			 shm->stats.reach_band_would_boost_high);
	}
}

/* Object-size-relative ARG_LEN draw observability.  The gate scalar
 * arg_len_semantics_draws stays zero while --arg-len-semantics is
 * off (the default), so the whole block is silent on baseline
 * runs.  See the struct-field comment in include/stats.h. */
static void dump_stats_render_arg_len_semantics(void)
{
	if (shm->stats.arg.len_semantics_draws) {
		stat_row("strategy", "arg_len_semantics_draws",
			 shm->stats.arg.len_semantics_draws);
		stat_row("strategy", "arg_len_objrelative_used",
			 shm->stats.arg.len_objrelative_used);
		stat_row("strategy", "arg_len_objrelative_nosize",
			 shm->stats.arg.len_objrelative_nosize);
		stat_row("strategy", "arg_len_objrel_blend_getlen",
			 shm->stats.arg.len_objrel_blend_getlen);
		stat_row("strategy", "arg_len_objrel_zero",
			 shm->stats.arg.len_objrel_zero);
		stat_row("strategy", "arg_len_objrel_one",
			 shm->stats.arg.len_objrel_one);
		stat_row("strategy", "arg_len_objrel_objsize",
			 shm->stats.arg.len_objrel_objsize);
		stat_row("strategy", "arg_len_objrel_objsize_minus_1",
			 shm->stats.arg.len_objrel_objsize_minus_1);
		stat_row("strategy", "arg_len_objrel_objsize_half",
			 shm->stats.arg.len_objrel_objsize_half);
		stat_row("strategy", "arg_len_objrel_pagesize",
			 shm->stats.arg.len_objrel_pagesize);
		stat_row("strategy", "arg_len_objrel_pagesize_plus_1",
			 shm->stats.arg.len_objrel_pagesize_plus_1);
		stat_row("strategy", "arg_len_objrel_pagesize_minus_1",
			 shm->stats.arg.len_objrel_pagesize_minus_1);
	}
}

/* SHADOW-ONLY wall-lever.  eligible_total / would_suppress_
 * total expose the data-driven gate's projected reclaim share on every
 * plateau-active pick; baseline_calls is the fleet mean per_syscall_
 * calls the predicate scaled WALL_LEVER_HIGH_MULT against.  See the
 * struct-field comment in include/stats.h. */
static void dump_stats_render_wall_lever_eligible(void)
{
	if (shm->stats.wall_lever_eligible_total) {
		stat_row("strategy", "wall_lever_eligible_total",
			 shm->stats.wall_lever_eligible_total);
		stat_row("strategy", "wall_lever_would_suppress_total",
			 shm->stats.wall_lever_would_suppress_total);
		stat_row("strategy", "wall_lever_baseline_calls",
			 __atomic_load_n(&shm->wall_lever_baseline_calls,
					 __ATOMIC_RELAXED));

		/* Top-N per-syscall would-suppress breakdown.  The aggregate
		 * total above is the headline reclaim projection a live
		 * variant would produce; this block exposes WHICH syscalls
		 * the projection is attributable to, so the budget can be
		 * audited by-syscall (against the existing top edge / pick
		 * blocks) BEFORE any live suppression is enabled.  Mirrors
		 * the absolute-totals top-N shape and biarch table choice
		 * the per-syscall edge top-N in dump_stats() already uses:
		 * under biarch only the 64-bit table is iterated -- 32-bit
		 * nrs collide with 64-bit ones in the same index space and
		 * would shadow them in the display. */
		{
			unsigned int top_nr[TOP_SYSCALLS_DUMP_TOPN];
			unsigned long top_vals[TOP_SYSCALLS_DUMP_TOPN];
			unsigned int top_count = 0;
			unsigned int nr_to_scan;
			const struct syscalltable *table;
			unsigned int i;
			int j;

			if (biarch) {
				nr_to_scan = max_nr_64bit_syscalls;
				table = syscalls_64bit;
			} else {
				nr_to_scan = max_nr_syscalls;
				table = syscalls;
			}
			if (nr_to_scan > MAX_NR_SYSCALL)
				nr_to_scan = MAX_NR_SYSCALL;

			memset(top_vals, 0, sizeof(top_vals));
			for (i = 0; i < nr_to_scan; i++) {
				unsigned long v = __atomic_load_n(
					&shm->stats.wall_lever_would_suppress[i],
					__ATOMIC_RELAXED);

				if (v == 0)
					continue;
				topn_push(top_vals, top_nr, &top_count,
					  TOP_SYSCALLS_DUMP_TOPN, v, i);
			}

			if (top_count > 0) {
				output(0, "Top wall-lever would-suppress "
					  "syscalls (shadow-only):\n");
				for (j = 0; j < (int)top_count; j++) {
					struct syscallentry *entry =
						table[top_nr[j]].entry;
					const char *name = entry ? entry->name
								 : "???";

					output(0, "  %-24s %lu\n",
					       name, top_vals[j]);
				}
			}
		}
	}
}

/* Unconditional wall-lever would-suppress observability.  The
 * sibling block above only renders when the predicate has
 * registered at least one eligible pick (wall_lever_eligible_total
 * != 0); this block surfaces the running would-suppress total and
 * its top-N per-syscall breakdown on EVERY dump so the projected
 * reclaim share + by-syscall attribution stay visible on runs
 * where the eligibility gate has not triggered yet.  Skip-zero on
 * the per-syscall scan + a top_count guard on the header suppress
 * the empty top-N; the scalar total renders unconditionally so a
 * 0 is an active "nothing accumulated" signal rather than silence.
 * Mirrors the biarch table choice + topn_push idiom used above. */
static void dump_stats_render_wall_lever_running(void)
{
	stat_row("strategy", "wall_lever_would_suppress_total",
		 shm->stats.wall_lever_would_suppress_total);
	{
		unsigned int top_nr[TOP_SYSCALLS_DUMP_TOPN];
		unsigned long top_vals[TOP_SYSCALLS_DUMP_TOPN];
		unsigned int top_count = 0;
		unsigned int nr_to_scan;
		const struct syscalltable *table;
		unsigned int i;
		int j;

		if (biarch) {
			nr_to_scan = max_nr_64bit_syscalls;
			table = syscalls_64bit;
		} else {
			nr_to_scan = max_nr_syscalls;
			table = syscalls;
		}
		if (nr_to_scan > MAX_NR_SYSCALL)
			nr_to_scan = MAX_NR_SYSCALL;

		memset(top_vals, 0, sizeof(top_vals));
		for (i = 0; i < nr_to_scan; i++) {
			unsigned long v = __atomic_load_n(
				&shm->stats.wall_lever_would_suppress[i],
				__ATOMIC_RELAXED);

			if (v == 0)
				continue;
			topn_push(top_vals, top_nr, &top_count,
				  TOP_SYSCALLS_DUMP_TOPN, v, i);
		}

		if (top_count > 0) {
			output(0, "Top wall-lever would-suppress "
				  "syscalls (running, shadow-only):\n");
			for (j = 0; j < (int)top_count; j++) {
				struct syscallentry *entry =
					table[top_nr[j]].entry;
				const char *name = entry ? entry->name
							 : "???";

				output(0, "  %-24s %lu\n",
				       name, top_vals[j]);
			}
		}
	}
}

void dump_stats_strategy_summary(void)
{
	if (shm->stats.bandit_cmp_reward_added)
		stat_row("strategy", "bandit_cmp_reward_added",
			 shm->stats.bandit_cmp_reward_added);
	if (shm->stats.bandit_edge_count_reward_added)
		stat_row("strategy", "bandit_edge_count_reward_added",
			 shm->stats.bandit_edge_count_reward_added);
	if (shm->stats.frontier.core.strategy_picks)
		stat_row("strategy", "frontier_strategy_picks",
			 shm->stats.frontier.core.strategy_picks);
	if (shm->stats.frontier.core.live_picks)
		stat_row("strategy", "frontier_live_picks",
			 shm->stats.frontier.core.live_picks);
	if (shm->stats.frontier.core.silent_picks)
		stat_row("strategy", "frontier_silent_picks",
			 shm->stats.frontier.core.silent_picks);
	/* SHADOW-ONLY observability companions to frontier_silent_picks:
	 * the candidate count (how many threshold-crossings the silent
	 * regime has produced) and the threshold itself, emitted side by
	 * side so the operator can interpret the count without consulting
	 * the source.  Neither value is read by the live picker math. */
	if (shm->stats.frontier.core.shadow_decay_candidates)
		stat_row("strategy", "frontier_shadow_decay_candidates",
			 shm->stats.frontier.core.shadow_decay_candidates);
	stat_row("strategy", "frontier_shadow_decay_streak_threshold",
		 FRONTIER_SHADOW_DECAY_STREAK);
	/* Tightened decay predicate (sibling of the looser counter above):
	 * adds the no-CMP-novelty + no-errno-shift UNLESS clause to the
	 * threshold-crossing test, and tallies the projected demote count
	 * across all silent-regime picks past the threshold.  The (looser
	 * candidates / candidates) ratio tells the operator what fraction
	 * of N-silent crossings the CMP/errno tightening would have spared;
	 * the would_skip / silent_picks ratio is the projected pick share a
	 * live silent-decay variant would demote. */
	if (shm->stats.frontier.cooldown.decay_candidates)
		stat_row("strategy", "frontier_decay_candidates",
			 shm->stats.frontier.cooldown.decay_candidates);
	if (shm->stats.frontier.cooldown.decay_would_skip)
		stat_row("strategy", "frontier_decay_would_skip",
			 shm->stats.frontier.cooldown.decay_would_skip);
	/* Arm-B-only live reject count for the silent-streak decay above.
	 * Pairs with frontier_decay_would_skip (both arms) as the headline
	 * arm-B behaviour delta; normalise against the Arm-B silent-pick
	 * throughput recoverable from frontier_silent_picks and the
	 * frontier_silent_decay_arm_{a,b}_children cohort split in kcov_shm. */
	if (shm->stats.frontier.cooldown.silent_decay_live_rejects)
		stat_row("strategy", "frontier_silent_decay_live_rejects",
			 shm->stats.frontier.cooldown.silent_decay_live_rejects);
	dump_stats_render_frontier_satcool();
	dump_stats_render_frontier_barren();
	dump_stats_render_frontier_cmp();
	/* SHADOW-ONLY LIVE-regime cooldown projections.  Sibling block to
	 * the silent-streak decay rows above: candidates is the distinct
	 * cooldown-episode count (one bump per FRONTIER_LIVE_MISS_COOLDOWN
	 * crossing per syscall); would_skip is the projected demote count a
	 * live cooldown variant of the picker would produce, normalised
	 * against frontier_live_picks for the projected reclaim fraction.
	 * The threshold is emitted alongside so the operator can interpret
	 * the candidate count without consulting the source, matching the
	 * frontier_shadow_decay_streak_threshold row above. */
	if (shm->stats.frontier.cooldown.live_cooldown_candidates)
		stat_row("strategy", "frontier_live_cooldown_candidates",
			 shm->stats.frontier.cooldown.live_cooldown_candidates);
	if (shm->stats.frontier.cooldown.live_would_skip)
		stat_row("strategy", "frontier_live_would_skip",
			 shm->stats.frontier.cooldown.live_would_skip);
	stat_row("strategy", "frontier_live_miss_cooldown_threshold",
		 FRONTIER_LIVE_MISS_COOLDOWN);
	dump_live_cooldown_would_skip_per_syscall_top();
	dump_stats_render_frontier_live_cool();
	dump_stats_render_context_regular_suppressed();
	/* Did-decay observability counter for the LIVE-regime early ring-
	 * decay path.  One bump per (nr, rotation) where the early ring-
	 * decay halved a non-zero cached sum.  Read alongside
	 * frontier_live_would_skip (F3 projection) to compare the projected
	 * vs the actually-applied cooldown volume; the ratio reflects how
	 * often the rotation-time decay catches a syscall the per-pick F3
	 * projection had already counted as a candidate. */
	if (shm->stats.frontier.cooldown.live_cooldown_decays)
		stat_row("strategy", "frontier_live_cooldown_decays",
			 shm->stats.frontier.cooldown.live_cooldown_decays);
	/* Blanket LIVE-regime probabilistic pick-reject (safe down-
	 * payment).  Reclaims ~1 / FRONTIER_LIVE_DECAY_REJECT_DENOM of
	 * LIVE-ring picks unconditionally; the reject rate against
	 * accepted picks is rejects / (rejects + frontier_live_picks)
	 * and should converge to 1 / REJECT_DENOM.  Read alongside
	 * frontier_live_would_skip (the F3 SHADOW projection) to gauge
	 * the headroom a targeted variant of this reject would unlock. */
	if (shm->stats.frontier.cooldown.live_decay_live_rejects)
		stat_row("strategy", "frontier_live_decay_live_rejects",
			 shm->stats.frontier.cooldown.live_decay_live_rejects);
	/* SHADOW + per-child A/B errno-plateau decay (silent-regime accept
	 * site): would_skip is the both-arms shadow demote count, live_
	 * rejects is the arm-B-only actual demote count, overlap_silent is
	 * the both-arms shadow count of picks where the consecutive-silent
	 * shadow predicate ALSO fires.  Emitted side by side with the
	 * silent-streak shadow rows above so the operator can read the
	 * orthogonal coverage (would_skip - overlap_silent) at a glance. */
	if (shm->stats.frontier.plateau.errno_decay_would_skip)
		stat_row("strategy", "frontier_errno_decay_would_skip",
			 shm->stats.frontier.plateau.errno_decay_would_skip);
	if (shm->stats.frontier.plateau.errno_decay_live_rejects)
		stat_row("strategy", "frontier_errno_decay_live_rejects",
			 shm->stats.frontier.plateau.errno_decay_live_rejects);
	if (shm->stats.frontier.plateau.errno_decay_overlap_silent)
		stat_row("strategy", "frontier_errno_decay_overlap_silent",
			 shm->stats.frontier.plateau.errno_decay_overlap_silent);
	dump_stats_render_frontier_blend();
	dump_stats_render_reach_band();
	/* Adaptive expensive-syscall accept gate.  All zero while the
	 * gate is in its default OFF mode (the early-return path skips
	 * the bumps).  See the expensive_adaptive_* field-comment block
	 * in include/stats.h for per-counter semantics. */
	if (shm->stats.expensive_adaptive.samples) {
		stat_row("strategy", "expensive_adaptive_samples",
			 shm->stats.expensive_adaptive.samples);
		stat_row("strategy", "expensive_adaptive_extra_accepts",
			 shm->stats.expensive_adaptive.extra_accepts);
		stat_row("strategy", "expensive_adaptive_demotes",
			 shm->stats.expensive_adaptive.demotes);
	}
	dump_stats_render_arg_len_semantics();
	if (shm->stats.frontier.core.underflow_prevented)
		stat_row("strategy", "frontier_underflow_prevented",
			 shm->stats.frontier.core.underflow_prevented);
	if (shm->stats.frontier.core.intervention_pulls)
		stat_row("strategy", "frontier_intervention_pulls",
			 shm->stats.frontier.core.intervention_pulls);
	if (shm->stats.frontier.core.intervention_cold_skipped)
		stat_row("strategy", "frontier_intervention_cold_skipped",
			 shm->stats.frontier.core.intervention_cold_skipped);
	if (shm->stats.plateau.forced_windows)
		stat_row("strategy", "plateau_forced_windows",
			 shm->stats.plateau.forced_windows);
	dump_stats_render_wall_lever_eligible();
	dump_stats_render_wall_lever_running();
	if (shm->stats.strategy_explorer_picks)
		stat_row("strategy", "strategy_explorer_picks",
			 shm->stats.strategy_explorer_picks);

	/* Cost-pool one-shot selector observer -- shutdown surface for
	 * the shadow / live accepted-pick counters bumped from the
	 * HEURISTIC and RANDOM arms in random-syscall.c.  Emitted in
	 * dump_stats_strategy_summary alongside the sibling frontier_
	 * satcool_* / frontier_live_cool_* shadow families above so an
	 * operator running a short dry-run (which never reaches the 600 s
	 * cost_pool_periodic_dump cadence) still sees the section 4.1
	 * identity numbers.  The if-non-zero guard keeps default-OFF
	 * runs' summary tail suppressed. */
	if (shm->stats.cost_pool_selector.shadow_picks)
		stat_row("strategy", "cost_pool_selector_shadow_picks",
			 shm->stats.cost_pool_selector.shadow_picks);
	if (shm->stats.cost_pool_selector.shadow_expensive_ppm_sum)
		stat_row("strategy",
			 "cost_pool_selector_shadow_expensive_ppm_sum",
			 shm->stats.cost_pool_selector.shadow_expensive_ppm_sum);
	if (shm->stats.cost_pool_selector.live_cheap_picks)
		stat_row("strategy", "cost_pool_selector_live_cheap_picks",
			 shm->stats.cost_pool_selector.live_cheap_picks);
	if (shm->stats.cost_pool_selector.live_expensive_picks)
		stat_row("strategy",
			 "cost_pool_selector_live_expensive_picks",
			 shm->stats.cost_pool_selector.live_expensive_picks);
	if (shm->stats.cost_pool_selector.predraw_cheap_picks)
		stat_row("strategy",
			 "cost_pool_selector_predraw_cheap_picks",
			 shm->stats.cost_pool_selector.predraw_cheap_picks);
	if (shm->stats.cost_pool_selector.predraw_expensive_picks)
		stat_row("strategy",
			 "cost_pool_selector_predraw_expensive_picks",
			 shm->stats.cost_pool_selector.predraw_expensive_picks);

	dump_strategy_stats();
}

