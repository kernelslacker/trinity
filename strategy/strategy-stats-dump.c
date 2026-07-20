/*
 * Operator-facing strategy summary printed at end of run.  Split from
 * strategy.c so the dump path compiles independently of the bandit /
 * picker / plateau / rescue / frontier translation units.
 */

#include <stdbool.h>

#include "compiler.h"		/* __cold */
#include "params.h"
#include "shm.h"
#include "stats.h"
#include "strategy.h"
#include "strategy-internal.h"

/*
 * Operator-facing summary, called from dump_stats() at end of run.
 * Always shows the picker mode (cheap context); per-arm pulls and
 * mean reward are printed in both modes whenever any window has
 * completed (total_pulls > 0) -- round-robin runs through
 * bandit_record_pull() too, so its per-arm yield is meaningful even
 * though the picker itself ignores the reward signal.  Suppressed
 * only when total_pulls is zero (run too short for any window to
 * close).
 */
static void dump_strategy_stats_header(void)
{
	enum picker_mode_t mode;

	mode = __atomic_load_n(&shm->picker_mode, __ATOMIC_RELAXED);

	output(0, "strategy picker: %s\n", picker_mode_name(mode));
}

/* Forced-intervention cohort.  These windows ran STRATEGY_RANDOM
 * over the picker's head because the kcov plateau detector
 * reported the fleet was stalled; their pulls/reward are
 * deliberately NOT folded into the per-arm bandit_pulls[] /
 * bandit_reward_calls[] series so a forced-RANDOM intervention
 * does not get conflated with a policy-chosen RANDOM in the
 * learner's history. */
static void dump_strategy_stats_plateau_forced_cohort(void)
{
	unsigned long plateau_forced;

	plateau_forced = __atomic_load_n(&shm->stats.plateau.forced_windows,
					 __ATOMIC_RELAXED);
	if (plateau_forced > 0)
		output(0, "  plateau-forced windows: %lu (forced over picker via SR_PLATEAU_FORCE, excluded from UCB learner)\n",
		       plateau_forced);
}

/* Plateau intervention mode rotation distribution.  Suppressed when
 * no plateau-forced window has run yet (plateau_forced == 0); when
 * it has, the per-mode window counts let the operator divide each
 * mode's contribution to rescue yield by the windows it actually
 * ran without reconstructing the rotation history from bandit_
 * pulls_by_reason.  The current mode line names what the next pick
 * during a live intervention would run; PIM_UNIFORM_RANDOM is the
 * resting value outside an intervention so a "current mode:
 * UNIFORM_RANDOM" reading at end-of-run is correct (the
 * orchestrator cleared the mode on the last non-intervention
 * rotation), not the most recent intervention mode. */
static void dump_strategy_stats_intervention_modes(void)
{
	unsigned long plateau_forced;

	plateau_forced = __atomic_load_n(&shm->stats.plateau.forced_windows,
					 __ATOMIC_RELAXED);

	if (plateau_forced > 0) {
		unsigned long mode_windows[NR_PIM_MODES];
		int pim;
		int cur_mode;

		for (pim = 0; pim < NR_PIM_MODES; pim++)
			mode_windows[pim] = __atomic_load_n(
				&shm->plateau_intervention_mode_windows[pim],
				__ATOMIC_RELAXED);

		output(0, "  intervention modes:");
		for (pim = 0; pim < NR_PIM_MODES; pim++)
			output(0, " %s=%lu",
			       plateau_intervention_mode_name(
				       (enum plateau_intervention_mode)pim),
			       mode_windows[pim]);
		output(0, "\n");

		cur_mode = __atomic_load_n(
			&shm->plateau_intervention_mode_current,
			__ATOMIC_RELAXED);
		if (cur_mode >= 0 && cur_mode < NR_PIM_MODES)
			output(0, "  intervention mode current: %s (live during an active plateau, resets to UNIFORM_RANDOM otherwise)\n",
			       plateau_intervention_mode_name(
				       (enum plateau_intervention_mode)cur_mode));

		/* Anti-prior baseline (mean per-syscall call count cached at
		 * the last PIM_ANTI_PRIOR rotation).  Zero means no
		 * anti-prior rotation has fired yet; non-zero means the
		 * accept gate has been live at some point with this
		 * baseline value as the inversion midpoint. */
		{
			unsigned long ap_baseline = __atomic_load_n(
				&shm->plateau_anti_prior_baseline_calls,
				__ATOMIC_RELAXED);
			if (ap_baseline > 0)
				output(0, "  anti-prior baseline: %lu calls/syscall (mean across active syscalls at last refresh)\n",
				       ap_baseline);
		}

	}
}

/* Random-rescue classifier distribution.  Per-class counts only
 * accumulate during SR_PLATEAU_FORCE intervention windows, so a
 * run that never plateaued prints nothing here; on a run that
 * did, the dominant class plus the currently-published
 * amplification field together tell the operator which targeted
 * intervention the orchestrator settled on by run-end.  Zero
 * buckets are suppressed so the placeholder classes (UNUSUAL_FD_
 * PRODUCER, WRONG_TYPE_FD, PERSONA_GATED) stay quiet until their
 * detection infrastructure lands and starts crediting rescues to
 * them. */
static void dump_strategy_stats_rescue_classes(void)
{
	unsigned long total_rescues = 0;
	int c;

	for (c = 0; c < RRC_NR_CLASSES; c++)
		total_rescues += __atomic_load_n(
			&shm->random_rescue_class_count[c],
			__ATOMIC_RELAXED);

	if (total_rescues > 0) {
		int amp = __atomic_load_n(
			&shm->plateau_rescue_amplified_class,
			__ATOMIC_RELAXED);

		output(0, "  rescue classes: total=%lu", total_rescues);
		for (c = 0; c < RRC_NR_CLASSES; c++) {
			unsigned long count = __atomic_load_n(
				&shm->random_rescue_class_count[c],
				__ATOMIC_RELAXED);
			if (count == 0)
				continue;
			output(0, " %s=%lu",
			       random_rescue_class_name(
				       (enum random_rescue_class)c),
			       count);
		}
		output(0, "\n");

		/* Amplified class is the orchestrator's current
		 * pick; RRC_NR_CLASSES means no class is being
		 * amplified (either the run is not in a plateau
		 * intervention right now or no class cleared the
		 * dominance threshold).  Print the threshold
		 * outcome explicitly so the operator can
		 * distinguish "no amplification because below
		 * floor" from "no amplification because the lead
		 * over the runner-up was too thin". */
		if (amp >= 0 && amp < RRC_NR_CLASSES)
			output(0, "  rescue amplified: %s (next intervention biased toward this class's structured replay)\n",
			       random_rescue_class_name(
				       (enum random_rescue_class)amp));
		else
			output(0, "  rescue amplified: none (no class crossed the %lu-rescue floor with a %lux lead)\n",
			       RRC_AMPLIFY_MIN_COUNT,
			       RRC_AMPLIFY_LEAD_RATIO);
	}
}

/* Hybrid bandit/explorer split summary.  Suppressed when the run had
 * no explorers reserved (explorer_children == 0) -- the bandit-pool
 * counter still ran but there is nothing to compare it against.
 *
 * Framed as a head-to-head competition: both pools feed the same
 * global KCOV edge bitmap and CMP bloom, so each first-discovery
 * edge is credited to whichever pool reached it first.  The lead
 * line shows the direct edge-share split so the operator can see
 * at a glance whether the always-on STRATEGY_RANDOM baseline is
 * stealing a disproportionate share of easy coverage from the
 * learned strategy.  Beyond the head-to-head line this block
 * derives:
 *   - per-child rate for each pool (edges / pool size), so the
 *     larger pool isn't credited just for having more workers
 *   - explorer fleet share for context against the edge share
 *   - one-line verdict (over-performing / at parity / under-)
 *     against the 2x-fleet-share threshold from the design doc.
 *     Hitting >=2x sustained across multiple runs is the trigger
 *     for considering per-child bandit (Option C). */
static void dump_strategy_stats_edge_race(void)
{
	unsigned long explorer_edges, bandit_edges;

	if (explorer_children > 0) {
		unsigned int bandit_children;
		unsigned long total_edges;
		unsigned long per_explorer, per_bandit;
		unsigned long ratio_x100;
		const char *verdict;

		explorer_edges = __atomic_load_n(
			&shm->stats.explorer_pool_edges_discovered,
			__ATOMIC_RELAXED);
		bandit_edges = __atomic_load_n(
			&shm->stats.bandit_pool_edges_discovered,
			__ATOMIC_RELAXED);
		bandit_children = max_children > explorer_children ?
			max_children - explorer_children : 0;
		total_edges = explorer_edges + bandit_edges;

		/* Per-child rate: rounded down to nearest whole edge.  A run
		 * too short for meaningful per-child rates renders as zero
		 * and that's an informative diagnostic. */
		per_explorer = explorer_edges / explorer_children;
		per_bandit = bandit_children > 0 ?
			bandit_edges / bandit_children : 0;

		/* Head-to-head competing-pools line.  The two pools both
		 * feed the same global KCOV edge bitmap and CMP bloom -- a
		 * first-discovery edge is credited to whichever pool reached
		 * it first, so the per-pool counters represent direct
		 * competition for the same coverage surface, not two
		 * independent measurements.  Render them on one line with
		 * the edge-share split as a percentage so the operator can
		 * see the head-to-head outcome at a glance, then break the
		 * components out beneath for the per-child rate. */
		if (total_edges > 0) {
			unsigned long e_share_pct_x10 =
				(explorer_edges * 1000UL) / total_edges;
			unsigned long b_share_pct_x10 = 1000UL - e_share_pct_x10;

			output(0, "  edge race: explorer %lu (%lu.%lu%%) vs bandit %lu (%lu.%lu%%) of %lu first-discovery edges\n",
			       explorer_edges,
			       e_share_pct_x10 / 10, e_share_pct_x10 % 10,
			       bandit_edges,
			       b_share_pct_x10 / 10, b_share_pct_x10 % 10,
			       total_edges);
		} else {
			output(0, "  edge race: explorer %lu vs bandit %lu (no edges yet)\n",
			       explorer_edges, bandit_edges);
		}
		output(0, "    explorer: %u children, %lu edges (%lu per child)\n",
		       explorer_children, explorer_edges, per_explorer);
		output(0, "    bandit:   %u children, %lu edges (%lu per child)\n",
		       bandit_children, bandit_edges, per_bandit);

		/* Edge-share verdict against the fleet-share-normalised
		 * ratio.  Suppressed on a zero-edge run or when there are
		 * no bandit children -- nothing meaningful to compare. */
		if (total_edges > 0 && bandit_children > 0) {
			unsigned int fleet_pct_x10 =
				explorer_children * 1000U / max_children;

			output(0, "    fleet share: explorer %u/%u children (%u.%u%%)\n",
			       explorer_children, max_children,
			       fleet_pct_x10 / 10U, fleet_pct_x10 % 10U);

			/* ratio = (explorer_edges / total_edges) /
			 *        (explorer_children / max_children)
			 * computed as a single integer division to avoid
			 * losing precision when the fleet share is tiny
			 * (e.g. --explorer-children=1 with -C16384). */
			ratio_x100 = (explorer_edges *
				      (unsigned long)max_children * 100UL) /
				     (total_edges *
				      (unsigned long)explorer_children);
			if (ratio_x100 >= 200)
				verdict = "explorer pool over-performing (>=2x fleet share -- per-child bandit trigger met)";
			else if (ratio_x100 <= 50)
				verdict = "explorer pool under-performing (bandit is winning the easy edges)";
			else
				verdict = "explorer pool at parity";
			output(0, "    verdict: %s (edge-share/fleet-share ratio %lu.%02lux)\n",
			       verdict,
			       ratio_x100 / 100, ratio_x100 % 100);
		}
	}
}

static void render_arm_summary(int i)
{
	unsigned long pulls = __atomic_load_n(&shm->bandit_pulls[i],
					      __ATOMIC_RELAXED);
	unsigned long reward = __atomic_load_n(
		&shm->bandit_reward_calls[i], __ATOMIC_RELAXED);
	unsigned long reward_pc_edges = __atomic_load_n(
		&shm->bandit_reward_pc_edge_count[i], __ATOMIC_RELAXED);
	unsigned long cmp_new = __atomic_load_n(
		&shm->bandit_cmp_new_constants[i], __ATOMIC_RELAXED);
	unsigned long share_sum = __atomic_load_n(
		&shm->bandit_cmp_share_sum_x1000[i], __ATOMIC_RELAXED);
	unsigned long mean_calls_x1000 = pulls ? (reward * 1000UL / pulls) : 0;
	/* Parallel mean for the real bucket-edge series, so the operator
	 * can eyeball how the two reward shapes would score each arm.
	 * Strictly >= the call-count mean (a call that produces N edges
	 * adds N to this series but only 1 to the call-count series). */
	unsigned long mean_pc_edges_x1000 =
		pulls ? (reward_pc_edges * 1000UL / pulls) : 0;
	/* Average per-window CMP share, parts per thousand.  Divides
	 * by total pulls (not just CMP-contributing pulls) so a low
	 * value can mean either "CMP rarely fires" or "CMP fires but
	 * is small relative to PC reward" — both are interesting for
	 * tuning the 0.25 weight constant. */
	unsigned long share_avg_x1000 = pulls ? (share_sum / pulls) : 0;

	output(0, "  arm[%d]: pulls=%lu reward_calls=%lu mean_calls=%lu.%03lu/window reward_edge_count=%lu mean_edge_count=%lu.%03lu/window cmp_novel=%lu cmp_share=%lu.%lu%%\n",
	       i, pulls, reward,
	       mean_calls_x1000 / 1000UL, mean_calls_x1000 % 1000UL,
	       reward_pc_edges,
	       mean_pc_edges_x1000 / 1000UL,
	       mean_pc_edges_x1000 % 1000UL,
	       cmp_new,
	       share_avg_x1000 / 10UL, share_avg_x1000 % 10UL);
}

/* Exposure line: per-arm syscall-level denominators alongside
 * the window-level reward summary above.  picks is the widest
 * population (all dispatched syscalls credited to the arm,
 * explorer included); bandit_ops is the strict bandit-pool
 * subset (picks - bandit_ops is the explorer contribution,
 * which is zero for non-RANDOM arms by construction);
 * completed is the count that reached the end of dispatch_step
 * without a set_syscall_nr FAIL upstream.  The
 * completed/picks ratio surfaces arms whose picker policy is
 * burning picks on unsatisfiable pick-side gates without
 * actually dispatching a call. */
static void render_arm_exposure(int i)
{
	unsigned long picks = __atomic_load_n(&shm->strategy_picks[i],
					      __ATOMIC_RELAXED);
	unsigned long bandit_ops = __atomic_load_n(
		&shm->strategy_bandit_pool_ops[i], __ATOMIC_RELAXED);
	unsigned long completed = __atomic_load_n(
		&shm->strategy_completed_calls[i], __ATOMIC_RELAXED);

	if (picks > 0) {
		unsigned long success_x1000 =
			(completed * 1000UL) / picks;
		output(0, "    exposure: picks=%lu bandit_ops=%lu completed=%lu (success=%lu.%lu%%)\n",
		       picks, bandit_ops, completed,
		       success_x1000 / 10UL, success_x1000 % 10UL);
	}
}

/* Reason breakdown: split this arm's window count and reward
 * by selection path.  Walk all reasons but only print the
 * ones with nonzero pulls so cold paths (e.g. SR_ROUND_ROBIN
 * under PICKER_BANDIT_UCB1, SR_PLATEAU_FORCE on a run that
 * never hit a plateau) stay quiet.  PLATEAU_FORCE rewards
 * appear here even though they are excluded from the
 * per-arm bandit_pulls / bandit_reward_calls totals above --
 * the per-reason matrix is exactly where the intervention
 * cohort's reward goes so the operator can size it against
 * the policy cohort.  Format: REASON=pulls/reward_calls, one
 * leading-space-indented continuation line per arm. */
static void render_arm_reasons(int i)
{
	bool any_reason = false;
	int r;

	for (r = 0; r < NR_SELECTION_REASONS; r++) {
		unsigned long rp = __atomic_load_n(
			&shm->bandit_pulls_by_reason[i][r],
			__ATOMIC_RELAXED);
		unsigned long rr = __atomic_load_n(
			&shm->bandit_reward_calls_by_reason[i][r],
			__ATOMIC_RELAXED);
		if (rp == 0)
			continue;
		if (!any_reason) {
			output(0, "    reasons:");
			any_reason = true;
		}
		output(0, " %s=%lu/%lu",
		       strategy_selection_reason_name(
			       (enum strategy_selection_reason)r),
		       rp, rr);
	}
	if (any_reason)
		output(0, "\n");
}

/* Chaos cohort breakdown: this arm's per-window WARN-fire
 * rate split by chaos state.  The chaos schedule fires every
 * CHAOS_WINDOW_MODULO'th window (1-in-8 today) and suppresses
 * cmp_hints injection for the duration, leaving the random
 * argument generator unbiased.  The V2 hypothesis is that
 * chaos-on windows produce measurably more kernel diagnostic
 * events than chaos-off windows -- the per-arm rate split
 * here is the headline observation.  Suppressed when both
 * cohorts are at zero pulls (arm never selected) so an arm
 * the picker has not visited stays quiet.  WARN fires are
 * rendered as parts per thousand of the cohort's pulls so the
 * two cohorts are directly comparable across orders of
 * magnitude difference in their window counts (chaos-on
 * cohort is ~1/(MODULO-1) the size of chaos-off in steady
 * state). */
static void render_arm_chaos(int i)
{
	unsigned long c_pulls[2], c_warn[2];
	int c;

	for (c = 0; c < 2; c++) {
		c_pulls[c] = __atomic_load_n(
			&shm->bandit_pulls_by_chaos[i][c],
			__ATOMIC_RELAXED);
		c_warn[c] = __atomic_load_n(
			&shm->bandit_warn_fires_by_chaos[i][c],
			__ATOMIC_RELAXED);
	}
	if (c_pulls[0] + c_pulls[1] > 0) {
		unsigned long off_rate_x1000 = c_pulls[0] ?
			(c_warn[0] * 1000UL / c_pulls[0]) : 0;
		unsigned long on_rate_x1000 = c_pulls[1] ?
			(c_warn[1] * 1000UL / c_pulls[1]) : 0;

		output(0, "    chaos: off=%lu/%lu (%lu.%03lu warn/window) on=%lu/%lu (%lu.%03lu warn/window)\n",
		       c_pulls[0], c_warn[0],
		       off_rate_x1000 / 1000UL,
		       off_rate_x1000 % 1000UL,
		       c_pulls[1], c_warn[1],
		       on_rate_x1000 / 1000UL,
		       on_rate_x1000 % 1000UL);
	}
}

static void dump_strategy_stats_arms(void)
{
	unsigned long total_pulls = 0;
	int i;

	for (i = 0; i < NR_STRATEGIES; i++)
		total_pulls += __atomic_load_n(&shm->bandit_pulls[i],
					       __ATOMIC_RELAXED);

	if (total_pulls == 0)
		return;

	for (i = 0; i < NR_STRATEGIES; i++) {
		render_arm_summary(i);
		render_arm_exposure(i);
		render_arm_reasons(i);
		render_arm_chaos(i);
	}
}

void __cold dump_strategy_stats(void)
{
	dump_strategy_stats_header();
	dump_strategy_stats_plateau_forced_cohort();
	dump_strategy_stats_intervention_modes();
	dump_strategy_stats_rescue_classes();
	dump_strategy_stats_edge_race();
	dump_strategy_stats_arms();
}
