/*
 * Bandit reward attribution and UCB1 arm-selection picker, split
 * from strategy.c.
 *
 * shm->pc_edge_calls_by_strategy[] is the reward signal the learner
 * consumes; pc_edge_count_by_strategy[] is diagnostic-only and does
 * not feed the picker.
 *
 * The picker runs once per STRATEGY_WINDOW: the CAS-winning child at
 * a rotation boundary calls pick_next_strategy() and
 * bandit_record_pull() and writes the outcome to shm->current_strategy.
 */

#include <math.h>
#include <stdbool.h>

#include "kcov.h"
#include "shm.h"
#include "stats.h"
#include "strategy.h"

/* Blended-reward mode.  Default OFF keeps the bandit reward total
 * byte-identical to today (call-count + weighted CMP novelty + the
 * transition secondary when its own mode is COMBINED).  See the
 * enum documentation in include/strategy.h for the SHADOW->COMBINED
 * ramp discipline this mirrors from kcov_transition_reward_mode. */
enum bandit_reward_edge_count_mode bandit_reward_edge_count_mode =
	BANDIT_REWARD_EDGE_COUNT_OFF;

/*
 * UCB1 exploration constant.  Standard derivation gives c = sqrt(2);
 * we leave it tunable because reward magnitudes (edges-per-window)
 * are not in [0,1] and the right exploration weight depends on the
 * normalisation choice.  Rewards are normalised by the largest
 * mean-reward observed across arms (see ucb1_score), so a c near 1
 * keeps the exploration term comparable to the exploit term.
 */
#define UCB1_EXPLORATION_C 1.41421356  /* sqrt(2) */

/*
 * EMA discount for the recent_pulls_x1000[]/recent_reward_x1000[]
 * counters defined in shm.h.  Each non-intervention window multiplies
 * every arm's counter by gamma = 1 - alpha, then increments the
 * active arm by 1.0 / window_reward.  Alpha = 0.05 gives a half-life
 * of log(0.5)/log(0.95) ≈ 13.5 windows -- around 22 minutes of fleet
 * wall time at the ~100 sec/window cadence, comfortably inside the
 * 10-30 window design target and short enough that the picker
 * recovers within a few rotations when an arm's yield collapses.
 *
 * BANDIT_EMA_SCALE is the fixed-point divisor: counters are stored
 * as their real value times 1000 so the integer math stays exact for
 * the alpha=0.05 step.
 */
#define BANDIT_EMA_ALPHA_X1000  50UL
#define BANDIT_EMA_SCALE        1000UL

/*
 * Decay one fixed-point counter by gamma = 1 - alpha.  Operates on
 * the parts-per-thousand value: 950/1000 stays integer and the
 * multiplication can't overflow because the inputs cap at
 * ~SCALE/alpha * (typical per-window reward) = a few million for
 * recent_pulls_x1000 (≤ 20000) and on the order of 1e9 for
 * recent_reward_x1000 (bounded by the headroom of unsigned long).
 */
static inline unsigned long bandit_ema_decay(unsigned long x_x1000)
{
	return (x_x1000 * (BANDIT_EMA_SCALE - BANDIT_EMA_ALPHA_X1000)
		+ BANDIT_EMA_SCALE / 2) /
	       BANDIT_EMA_SCALE;
}

/*
 * Record the just-finished window: bump pull count for the arm that
 * was active, add its edge yield plus the CMP-novelty term to the
 * cumulative reward, and update the diagnostic CMP-share running sum.
 * Called by the CAS-winning child during maybe_rotate_strategy(),
 * which serialises with the picker — so picker-side reads of
 * bandit_pulls[] / bandit_reward_calls[] / bandit_reward_pc_edge_count[]
 * / bandit_cmp_share_sum_x1000[] inside pick_next_strategy() are
 * covered by the strategy-switch store's release semantics on the
 * next CAS winner.
 *
 * dump_strategy_stats() is parent-side and runs outside the CAS
 * protocol, so it can race a child that is mid-update here.  To keep
 * its per-arm reads from tearing against these writes, the writes use
 * __atomic_fetch_add(..., RELAXED) and dump_strategy_stats() pairs
 * them with __atomic_load_n(..., RELAXED).  Relaxed is sufficient: the
 * dump is a diagnostic snapshot with no ordering requirement against
 * other shm fields.  The stats counter bump uses an atomic add for the
 * same reason.
 *
 * pc_edge_calls is the per-window pc_edge_calls_by_strategy delta
 * (calls with >=1 new edge).  pc_edge_count is the parallel
 * pc_edge_count_by_strategy delta (real bucket-edge bits flipped).
 * cmp_new_constants is the per-window bandit_cmp_new_constants delta.
 *
 * The learner-facing combined reward is
 *   pc_edge_calls + cmp_new_constants / CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL
 * (integer division — sub-weight CMP residues round to zero so a
 * window with a handful of novel constants doesn't perturb the
 * headline PC signal).  The pc_edge_count delta accumulates into the
 * parallel diagnostic reward (no cmp term folded in) so the operator
 * can compare what the real-count reward would have looked like.
 */
void bandit_record_pull(int arm, enum strategy_selection_reason reason,
			unsigned long pc_edge_calls,
			unsigned long pc_edge_count,
			unsigned long cmp_new_constants,
			unsigned long warn_fires,
			bool was_chaos)
{
	unsigned long cmp_term;
	unsigned long trans_term;
	unsigned long edge_count_term;
	enum bandit_reward_edge_count_mode ec_mode;
	unsigned long total;
	unsigned int chaos_idx;
	int i;

	if (arm < 0 || arm >= NR_STRATEGIES)
		return;
	if (reason < 0 || reason >= NR_SELECTION_REASONS)
		return;

	cmp_term = cmp_new_constants / CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL;

	/* Transition-reward window delta.  Read from shm->stats directly
	 * rather than threaded through a new parameter so the function
	 * signature (and its declaration in include/strategy.h) stays
	 * unchanged.  The transition window-start snapshot is reseeded
	 * during the rotation handler in maybe_rotate_strategy (random-
	 * syscall.c) at the same RELAXED cadence as the pc_edge_*_at_
	 * window_start pair; computing the delta here is symmetric to how
	 * maybe_rotate_strategy computes pc_edge_calls / pc_edge_count
	 * before calling in.
	 *
	 * trans_term divides the raw transition delta by TRANSITION_BANDIT_
	 * REWARD_WEIGHT_RECIPROCAL (= 4, a 0.25 secondary weight matching
	 * the CMP-term shape) and is added only under COMBINED mode.  The
	 * per-call cap that prevents one pathological trace from
	 * monopolizing the window lives at the source bump in random-
	 * syscall.c (TRANSITION_PER_CALL_REWARD_CAP); no additional cap
	 * is needed here.  Under SHADOW_ONLY/OFF trans_term stays zero so
	 * the bandit reward total is byte-identical to the pre-knob
	 * baseline. */
	if (__atomic_load_n(&kcov_transition_reward_mode,
			    __ATOMIC_RELAXED) ==
	    KCOV_TRANSITION_REWARD_COMBINED) {
		unsigned long trans_now = __atomic_load_n(
			&shm->stats.transition_edge.count_by_strategy[arm],
			__ATOMIC_RELAXED);
		unsigned long trans_start = __atomic_load_n(
			&shm->stats.transition_edge.count_at_window_start,
			__ATOMIC_RELAXED);
		unsigned long trans_delta = (trans_now >= trans_start) ?
					     (trans_now - trans_start) : 0UL;

		trans_term = trans_delta /
			     TRANSITION_BANDIT_REWARD_WEIGHT_RECIPROCAL;
	} else {
		trans_term = 0;
	}

	/* Blended edge-count secondary reward.  Read the mode once so
	 * shadow accounting and the fold-into-total decision cannot drift
	 * against each other if the operator toggles the knob mid-run
	 * (nothing does today, but the RELAXED load is trivially cheap
	 * and keeps the two branches consistent).  Under OFF the term
	 * stays zero and no shadow counter bumps -- byte-identical to
	 * the pre-knob reward path.  Under SHADOW_ONLY / COMBINED compute
	 * edge_count_term = pc_edge_count /
	 * EDGE_COUNT_BANDIT_REWARD_WEIGHT_RECIPROCAL and bump the
	 * bandit_edge_count_reward_added shadow counter on every
	 * non-forced window where the term is non-zero, so the SHADOW
	 * ramp exposes how often COMBINED would move the reward before
	 * the mode is promoted.  Only COMBINED folds the term into the
	 * ucb1-facing total below. */
	ec_mode = __atomic_load_n(&bandit_reward_edge_count_mode,
				  __ATOMIC_RELAXED);
	if (ec_mode == BANDIT_REWARD_EDGE_COUNT_OFF) {
		edge_count_term = 0;
	} else {
		edge_count_term = pc_edge_count /
				  EDGE_COUNT_BANDIT_REWARD_WEIGHT_RECIPROCAL;
	}

	total = pc_edge_calls + cmp_term + trans_term;
	if (ec_mode == BANDIT_REWARD_EDGE_COUNT_COMBINED)
		total += edge_count_term;

	/* Always bucket the just-finished window by (arm, reason) before
	 * any cohort-gated learner update.  These matrices are diagnostic
	 * (the picker does not score against them) so they capture every
	 * window including SR_PLATEAU_FORCE -- intervention reward is the
	 * exact signal a future plateau-rescue classifier wants to read
	 * back, and excluding it here would silently zero the cohort the
	 * classifier is meant to study. */
	__atomic_fetch_add(&shm->bandit_pulls_by_reason[arm][reason], 1UL,
			   __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->bandit_reward_calls_by_reason[arm][reason],
			   total, __ATOMIC_RELAXED);
	__atomic_fetch_add(
		&shm->bandit_reward_pc_edge_count_by_reason[arm][reason],
		pc_edge_count, __ATOMIC_RELAXED);

	/* SR_PLATEAU_FORCE windows skip the learner-facing updates: an
	 * intervention window ran STRATEGY_RANDOM because every arm was
	 * stalled, which is structurally different from "RANDOM scored
	 * best under UCB" (the bandit had no input on the pick).  Folding
	 * the forced window into bandit_pulls[] / bandit_reward_calls[] /
	 * the recent_*_x1000 EMA contaminates the learner so the bandit
	 * can't tell policy-chosen RANDOM windows from forced RANDOM
	 * windows once the plateau clears.  The SR_PLATEAU_FORCE guard
	 * lives here, after the by-reason bucketing, keeping bucketing
	 * unconditional regardless of plateau state. */
	if (reason == SR_PLATEAU_FORCE)
		return;

	/* Per-arm x chaos-state cohort attribution -- chaos-mode V2.  Sits
	 * below the SR_PLATEAU_FORCE early-return so the by_chaos cohort
	 * sums reconcile with the flat bandit_pulls[] / bandit_reward_calls[]
	 * totals updated immediately below: an intervention window that
	 * lands inside a chaos window must drop from both cohorts together,
	 * otherwise sum_arm sum_chaos bandit_pulls_by_chaos[arm][c] runs
	 * ahead of sum_arm bandit_pulls[arm] by the SR_PLATEAU_FORCE count
	 * and the operator-facing cohort ratio drifts.
	 *
	 * was_chaos is sampled by the caller in maybe_rotate_strategy
	 * before cmp_hints_chaos_tick advances the schedule, so it reflects
	 * the chaos state in effect across the just-finished window rather
	 * than the state for the upcoming one.  The warn_fires delta is the
	 * caller-computed kmsg_warn_fires_now - kmsg_warn_fires_at_window_
	 * start delta for the same window.  Observation only -- no consumer
	 * in select_next_strategy or ucb1_score reads these arrays; V3
	 * action mode will wire them into the picker once the significance
	 * gate from the design doc clears. */
	chaos_idx = was_chaos ? 1u : 0u;
	__atomic_fetch_add(&shm->bandit_pulls_by_chaos[arm][chaos_idx], 1UL,
			   __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->bandit_reward_calls_by_chaos[arm][chaos_idx],
			   total, __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->bandit_warn_fires_by_chaos[arm][chaos_idx],
			   warn_fires, __ATOMIC_RELAXED);

	__atomic_fetch_add(&shm->bandit_pulls[arm], 1UL, __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->bandit_reward_calls[arm], total,
			   __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->bandit_reward_pc_edge_count[arm],
			   pc_edge_count, __ATOMIC_RELAXED);

	/* Shadow-firing counter for the edge-count secondary reward.  Fires
	 * on every non-forced window where the term is non-zero, under
	 * both SHADOW_ONLY (term computed but not folded into total) and
	 * COMBINED (term folded above).  Placed here alongside the
	 * learner-facing bandit_pulls[] / bandit_reward_pc_edge_count[]
	 * bumps so a reader can join the three series at the same cadence.
	 * Sibling of bandit_cmp_reward_added below -- see the field
	 * comment in include/stats.h for the ramp semantics. */
	if (edge_count_term > 0)
		__atomic_fetch_add(&shm->stats.picker_bandit.edge_count_reward_added,
				   1UL, __ATOMIC_RELAXED);

	/* Discounted "recent" series update.  Decay every arm's counters
	 * by gamma = 1 - alpha first, THEN credit the active arm with one
	 * effective pull and the window's reward.  Decaying all arms (not
	 * just the pulled one) is what keeps the UCB1 explore-term
	 * denominator meaningful under discounting -- an arm that stops
	 * being picked must see its effective sample count shrink so the
	 * picker eventually re-tries it.  Single writer (CAS-serialised
	 * rotation path) so plain reads of the old values are safe;
	 * RELEASE stores back so the parent-side dump's RELAXED loads see
	 * complete values rather than torn intermediates.  This update
	 * runs alongside the lifetime fields above; ucb1_score() reads the
	 * recent series for both exploit and explore terms (D-UCB), while
	 * cold-start in pick_next_strategy() reads the lifetime by-reason
	 * aggregate (sum across r of bandit_pulls_by_reason[i][r]) -- "never
	 * observed by any path, including SR_PLATEAU_FORCE" rather than
	 * "not observed lately" -- and the lifetime fields also back
	 * dump_strategy_stats. */
	for (i = 0; i < NR_STRATEGIES; i++) {
		unsigned long p = __atomic_load_n(&shm->recent_pulls_x1000[i],
						  __ATOMIC_RELAXED);
		unsigned long r = __atomic_load_n(&shm->recent_reward_x1000[i],
						  __ATOMIC_RELAXED);

		__atomic_store_n(&shm->recent_pulls_x1000[i],
				 bandit_ema_decay(p), __ATOMIC_RELAXED);
		__atomic_store_n(&shm->recent_reward_x1000[i],
				 bandit_ema_decay(r), __ATOMIC_RELAXED);
	}
	__atomic_fetch_add(&shm->recent_pulls_x1000[arm], BANDIT_EMA_SCALE,
			   __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->recent_reward_x1000[arm],
			   total * BANDIT_EMA_SCALE, __ATOMIC_RELAXED);

	if (cmp_term == 0)
		return;

	__atomic_fetch_add(&shm->stats.picker_bandit.cmp_reward_added, 1UL,
			   __ATOMIC_RELAXED);

	/* Per-arm running sum of cmp_term's share of the combined reward,
	 * scaled to parts per thousand.  Total is non-zero here because
	 * cmp_term > 0.  Averaged at end-of-run to surface the empirical
	 * CMP weighting per arm so the 0.25 constant can be tuned. */
	__atomic_fetch_add(&shm->bandit_cmp_share_sum_x1000[arm],
			   (cmp_term * 1000UL) / total,
			   __ATOMIC_RELAXED);
}

/*
 * Compute the UCB1 score for one arm.  Discounted formulation
 * (D-UCB): the lifetime bandit_pulls[]/bandit_reward_calls[] series
 * is replaced by the rolling exponentially-decayed counters
 * recent_pulls_x1000[]/recent_reward_x1000[] so the picker tracks
 * recent yield instead of the lifetime average.  Kernel coverage
 * discovery is non-stationary -- early windows mine out easy edges
 * and late windows degrade -- so an arm's last few windows are the
 * relevant signal, not its 2024 mean.
 *
 *     score_i = mean_reward_i / norm + c * sqrt(ln(N) / n_i)
 *
 * where:
 *   mean_reward_i = recent_reward_x1000[i] / recent_pulls_x1000[i]
 *                   (the x1000 fixed-point cancels, leaving the
 *                   discounted mean reward in the original calls
 *                   units the lifetime series used)
 *   norm          = max over arms of mean_reward_j (or 1 if all zero)
 *   N             = sum across arms of n_j (effective discounted
 *                   sample size, the D-UCB analogue of total_pulls)
 *   n_i           = recent_pulls_x1000[i] / 1000.0
 *   c             = UCB1_EXPLORATION_C
 *
 * Normalising the exploit term by the largest observed mean keeps it
 * in roughly the same range as the exploration term (~1) regardless
 * of whether per-window rewards are in the hundreds or hundreds of
 * thousands.  Without normalisation, a UCB1 picker over edges-per-
 * window degenerates into "always pick the arm with the highest
 * cumulative average" because the exploit term dwarfs sqrt(ln/n).
 *
 * The reward signal consumed here is still the CALL-COUNT series
 * (recent_reward_x1000[] is the discounted form of
 * bandit_reward_calls[] -- calls-with-≥1-edge plus the weighted CMP
 * novelty term).  The parallel real bucket-count series
 * (bandit_reward_pc_edge_count[]) remains a lifetime diagnostic and
 * does not feed the score; switching the learner to a discounted
 * bucket-count signal is a separate decision once both signals have
 * been observed under discounting against real run data.
 *
 * pulls_x1000 == 0 clamps to 1: an arm whose discounted count
 * decayed all the way to zero (≈140 windows of no selection at
 * gamma=0.95) is by definition starved, the resulting huge explore
 * term is the correct outcome.  The clamp keeps the division
 * well-defined rather than relying on a separate guard.
 */
static double ucb1_score(int arm, double total_n, double norm)
{
	unsigned long pulls_x1000 = __atomic_load_n(&shm->recent_pulls_x1000[arm],
						    __ATOMIC_RELAXED);
	unsigned long reward_x1000 = __atomic_load_n(&shm->recent_reward_x1000[arm],
						     __ATOMIC_RELAXED);
	double n_i, mean, exploit, explore;

	if (pulls_x1000 == 0)
		pulls_x1000 = 1;

	n_i = (double)pulls_x1000 / (double)BANDIT_EMA_SCALE;
	mean = (double)reward_x1000 / (double)pulls_x1000;
	exploit = mean / norm;
	explore = UCB1_EXPLORATION_C * sqrt(log(total_n) / n_i);

	return exploit + explore;
}

/*
 * Sum across reasons of the by-reason pull matrix.  Used by the
 * cold-start scan so an arm exercised under SR_PLATEAU_FORCE counts
 * as "has been selected": bandit_pulls[] is deliberately not bumped
 * on forced-intervention windows (see bandit_record_pull) so the UCB
 * learner's reward history stays clean, but bandit_pulls_by_reason[]
 * captures every window unconditionally, and summing across reasons
 * gives the true "ever picked?" answer that cold-start wants.
 * NR_STRATEGIES * NR_SELECTION_REASONS is currently 12 cells; the
 * cold-start scan only fires until each eligible arm has been picked
 * once, so the cost is irrelevant.
 */
static unsigned long bandit_total_picks(int arm)
{
	unsigned long total = 0;
	int r;

	for (r = 0; r < NR_SELECTION_REASONS; r++)
		total += __atomic_load_n(&shm->bandit_pulls_by_reason[arm][r],
					 __ATOMIC_RELAXED);
	return total;
}

/*
 * Pick the arm to run during the next window using the configured
 * arm-selection POLICY only.  Returns an index in [0, NR_STRATEGIES)
 * and writes the reason path through *reason_out.  The caller
 * (maybe_rotate_strategy via select_next_strategy) has already
 * updated bandit_pulls[]/bandit_reward_calls[] (plus the parallel
 * bandit_reward_pc_edge_count[] diagnostic series) AND the
 * discounted recent_pulls_x1000[]/recent_reward_x1000[] series for
 * the just-finished window unless that window was a forced
 * intervention.  UCB1 scoring reads the discounted recent series
 * (D-UCB, see ucb1_score) so non-stationary kernel coverage
 * discovery doesn't let early-run wins dominate late-run picks.
 *
 * Cold-start: any arm that has never been selected by any path --
 * UCB pick, round-robin, prior cold-start, or plateau-force --
 * wins immediately (UCB1's convention: every arm gets one pull
 * before the score formula makes sense).  The trigger reads the
 * lifetime by-reason aggregate rather than bandit_pulls[] so a
 * plateau-force window counts as "selected" even though the
 * learner-facing bandit_pulls[] is deliberately not bumped on
 * forced rotations (see bandit_record_pull).  Lifetime rather than
 * discounted pulls because cold-start is a once-per-arm trigger;
 * using the decayed count would re-fire after the discount horizon
 * and turn the learner into slow round-robin.  Ties broken in
 * favour of the lower index, which keeps the warm-up deterministic.
 *
 * Round-robin mode bypasses the bandit entirely and just steps to
 * the next arm — same behaviour as Phase 1.
 *
 * Plateau interventions live in select_next_strategy(); this picker
 * is pure policy (keeps forced-intervention windows out of the UCB
 * learner's pull/reward history).
 */
int pick_next_strategy(int prev, enum strategy_selection_reason *reason_out)
{
	enum picker_mode_t mode;
	bool eligible[NR_STRATEGIES];
	double total_n = 0.0;
	double max_mean = 0.0;
	double best_score;
	int best_arm = -1;
	int i;

	/* Empty active-syscall pool guard.  If every syscall has been
	 * deactivated (either nr_active_syscalls on uniarch, or both 32/64
	 * counters on biarch), the per-arm weighting below has nothing
	 * meaningful to score and can silently land on a non-RANDOM arm
	 * whose strategy routine has no useful work to do.  Short-circuit
	 * to STRATEGY_RANDOM -- the random picker copes with an empty pool
	 * via its own fallbacks -- and emit a one-shot log so the
	 * degenerate condition is visible without spamming. */
	if (shm->nr_active_syscalls == 0 &&
	    shm->nr_active_32bit_syscalls == 0 &&
	    shm->nr_active_64bit_syscalls == 0) {
		static bool warned;
		if (!warned) {
			warned = true;
			outputerr("pick_next_strategy: active-syscall pool empty -- forcing STRATEGY_RANDOM\n");
		}
		*reason_out = SR_NORMAL_UCB;
		return STRATEGY_RANDOM;
	}

	mode = __atomic_load_n(&shm->picker_mode, __ATOMIC_RELAXED);

	/* Cache per-arm eligibility once.  No arm has an expensive precondition
	 * today, but the hook stays so a future arm with one slots in here
	 * without changing the picker dispatch. */
	for (i = 0; i < NR_STRATEGIES; i++)
		eligible[i] = is_strategy_eligible(i);

	if (mode == PICKER_ROUND_ROBIN) {
		int next = prev;
		*reason_out = SR_ROUND_ROBIN;
		for (i = 0; i < NR_STRATEGIES; i++) {
			next = (next + 1) % NR_STRATEGIES;
			if (eligible[next])
				return next;
		}
		/* Every arm ineligible — should not happen because at least
		 * STRATEGY_HEURISTIC and STRATEGY_RANDOM have no preconditions.
		 * Fall back to the historical Phase 1 behaviour rather than
		 * returning -1 to a caller that expects a valid index. */
		return (prev + 1) % NR_STRATEGIES;
	}

	/* Cold-start reads the LIFETIME by-reason aggregate (see
	 * bandit_total_picks) rather than the learner-facing
	 * bandit_pulls[i].  bandit_pulls[] is deliberately not bumped on
	 * SR_PLATEAU_FORCE windows -- forced-intervention rotations are
	 * excluded from the UCB reward history so the learner can't
	 * confuse a policy-chosen STRATEGY_RANDOM window with a
	 * plateau-forced one -- so an arm that has only ever been
	 * exercised under plateau-force still reads zero in
	 * bandit_pulls[].  Keying cold-start off that would keep firing
	 * for the same arm every rotation, trapping the picker behind
	 * the forced-RANDOM slot under low fleet iter rates and starving
	 * the remaining arms.  The by-reason aggregate captures every
	 * window (including SR_PLATEAU_FORCE) so it treats "selected at
	 * least once by any path" as cold-start-satisfying; bandit_pulls[]
	 * still gates UCB scoring.  Recent (discounted) pulls are
	 * intentionally NOT consulted here -- cold-start is a "never
	 * observed" trigger, not a "haven't been observed lately" one,
	 * and reading recent_pulls_x1000 would re-fire cold-start every
	 * ~140 windows for any arm the picker has stopped choosing. */
	for (i = 0; i < NR_STRATEGIES; i++) {
		if (!eligible[i])
			continue;
		if (bandit_total_picks(i) == 0) {
			*reason_out = SR_COLD_START;
			return i;
		}
	}

	/* total_n: sum of discounted effective-sample counts across
	 * eligible arms.  D-UCB analogue of vanilla UCB1's "total pulls"
	 * in the ln(N) explore-term numerator.  Floor at 1.0 so log()
	 * stays non-negative on a fresh post-cold-start run where the
	 * sum hasn't grown above unity yet. */
	for (i = 0; i < NR_STRATEGIES; i++) {
		if (!eligible[i])
			continue;
		total_n += (double)__atomic_load_n(&shm->recent_pulls_x1000[i],
						   __ATOMIC_RELAXED) /
			   (double)BANDIT_EMA_SCALE;
	}
	if (total_n < 1.0)
		total_n = 1.0;

	/* Normalise by the largest discounted mean-reward across eligible
	 * arms so the exploit term lives in the same numeric range as the
	 * exploration term.  Falls back to 1.0 when every arm has yielded
	 * zero edges in the recent horizon (well-defined and harmless).
	 * Skips arms whose discounted pulls decayed to zero -- their
	 * "mean" is undefined, and they will get a huge explore-term
	 * score from ucb1_score's pulls_x1000==0 clamp so the picker will
	 * re-try them on this pass anyway. */
	for (i = 0; i < NR_STRATEGIES; i++) {
		unsigned long p, r;
		double mean;

		if (!eligible[i])
			continue;
		p = __atomic_load_n(&shm->recent_pulls_x1000[i],
				    __ATOMIC_RELAXED);
		r = __atomic_load_n(&shm->recent_reward_x1000[i],
				    __ATOMIC_RELAXED);
		if (p == 0)
			continue;
		mean = (double)r / (double)p;
		if (mean > max_mean)
			max_mean = mean;
	}
	if (max_mean <= 0.0)
		max_mean = 1.0;

	best_score = -1.0;
	for (i = 0; i < NR_STRATEGIES; i++) {
		double s;

		if (!eligible[i])
			continue;
		s = ucb1_score(i, total_n, max_mean);
		if (best_arm < 0 || s > best_score) {
			best_score = s;
			best_arm = i;
		}
	}
	if (best_arm < 0)
		best_arm = STRATEGY_HEURISTIC;
	*reason_out = SR_NORMAL_UCB;
	return best_arm;
}
