/*
 * Multi-strategy syscall-picker rotation: glue, configuration, and
 * the plateau-intervention dispatch layer.
 *
 * Picker mode is selected once at parse_args() time via --strategy
 * and stashed in shm->picker_mode so every child agrees on the
 * policy.
 *
 * The bandit learner itself (reward attribution + UCB1 scoring +
 * pure arm-selection policy) lives in strategy-bandit.c.  The
 * intervention layer in select_next_strategy() below sits one level
 * above that picker: when kcov reports the fleet's edge-discovery
 * rate is stalled, it forces STRATEGY_RANDOM (or one of the
 * intervention modes) with reason SR_PLATEAU_FORCE without
 * consulting the UCB scorer, so the bandit is shaken out of
 * whatever local minimum it has settled into.  The rotation site
 * checks the stamped reason at window close and skips the
 * bandit_record_pull() call for SR_PLATEAU_FORCE windows so the
 * learner's reward history stays clean of intervention noise.
 *
 * Round-robin mode bypasses the intervention -- its own cycling
 * already includes RANDOM, and forcing it here would collapse the
 * cycle to one arm.
 *
 * Future dispatches will replace the "force STRATEGY_RANDOM" policy
 * with smarter interventions (e.g. a classifier that picks the arm
 * most likely to break the stall) inside this function; the
 * separation between intervention and learner keeps that work from
 * disturbing the UCB scoring path.
 */

#include <stdbool.h>
#include <string.h>

#include "kcov.h"
#include "shm.h"
#include "stats.h"
#include "strategy.h"
#include "strategy-internal.h"

/*
 * Set by parse_args() before init_shm() runs, then propagated into
 * shm->picker_mode where every child reads it on the rotation path.
 * Not declared in a header — only params.c writes it and only
 * init_shm() reads it.
 *
 * Default is PICKER_BANDIT_UCB1: the plateau-intervention layer in
 * select_next_strategy() is bandit-gated, and the mode-aware default
 * for explorer_children (see clamp_default_explorer_children() in
 * params.c) only allocates the strategy-independent explorer pool
 * under bandit mode.  Defaulting to round-robin made both of those
 * adaptive paths silently inert -- a plateau under the round-robin
 * default would flip kcov_shm->plateau_active with nothing on the
 * picker side to respond.  --strategy=round-robin (alias rr) and
 * --strategy=bandit (aliases ucb1, bandit-ucb1) remain available as
 * explicit overrides.
 */
enum picker_mode_t picker_mode_arg = PICKER_BANDIT_UCB1;

/*
 * Saturation-cooldown mode.  Default OFF keeps the silent-regime
 * accept path byte-identical to today; SHADOW_ONLY enables the
 * corrected predicate's shadow accounting without changing live
 * selection.  See the enum comment in include/strategy.h for the
 * mode contract and the ramp discipline.  Param-settable via
 * --frontier-saturation-cooldown=off|shadow-only|combined.
 */
enum frontier_saturation_cooldown_mode frontier_saturation_cooldown_mode =
	FRONTIER_SATURATION_COOLDOWN_MODE_OFF;

/*
 * LIVE-regime cooldown discriminator mode.  Default OFF keeps the
 * LIVE-regime miss-attribution path byte-identical to today;
 * SHADOW_ONLY enables the discriminator's shadow accounting (which
 * spare lane fires per cool-eligible nr) without changing the live
 * picker decision.  See the enum comment in include/strategy.h for
 * the mode contract and the ramp discipline.  Param-settable via
 * --frontier-live-cooldown-mode=off|shadow-only|combined.
 */
enum frontier_live_cooldown_mode frontier_live_cooldown_mode =
	FRONTIER_LIVE_COOLDOWN_MODE_OFF;

/*
 * Floored-barren sub-floor demote mode.  Default OFF keeps the silent-
 * regime accept path byte-identical to today; SHADOW_ONLY enables the
 * vetted floored-barren predicate's shadow accounting (how many
 * silent-regime picks a COMBINED sub-floor variant would demote)
 * without changing live selection.  See the enum comment in
 * include/strategy.h for the mode contract and the ramp discipline.
 * Param-settable via
 * --frontier-barren-demote=off|shadow-only|combined.
 */
enum frontier_barren_demote_mode frontier_barren_demote_mode =
	FRONTIER_BARREN_DEMOTE_MODE_OFF;

/*
 * Heuristic-arm group-bias anti-lock-in damper mode.  Default OFF
 * keeps the dispatch-step per-child bookkeeping (group-change streak
 * reset, fd-warm bump, coverage watermark advance) and the
 * group_bias-gate shadow predicate evaluation entirely dormant -- no
 * per-child field touched, no atomic loads, no shadow counters bump.
 * SHADOW_ONLY engages the bookkeeping + predicate without changing
 * live selection.  See the enum comment in include/strategy.h for the
 * mode contract and the ramp discipline.  Param-settable via
 * --frontier-group-antilock=off|shadow-only|combined.
 */
enum frontier_group_antilock_mode frontier_group_antilock_mode =
	FRONTIER_GROUP_ANTILOCK_MODE_OFF;

/*
 * Cost-pool one-shot selector mode.  Default OFF keeps the HEURISTIC
 * and RANDOM picker arms byte-identical to today; SHADOW_ONLY engages
 * the closed-form coin-then-draw observer that accumulates per-pool
 * expected fractions into cost_pool_selector_shadow_* counters
 * without changing live selection or consuming any RNG.  See the enum
 * comment in include/strategy.h for the mode contract and the ramp
 * discipline.  Param-settable via
 * --cost-pool-selector=off|shadow-only|combined.
 */
enum cost_pool_selector_mode cost_pool_selector_mode =
	COST_POOL_SELECTOR_MODE_OFF;

/*
 * Context-pool mode -- Path-A "regular_suppressed" shadow projection.
 * Default OFF keeps the picker pick-finalise site byte-identical to
 * today; SHADOW_ONLY engages the data-gated classifier + context_
 * regular_suppressed_* counter bumps without changing live selection.
 * See the enum comment in include/strategy.h for the mode contract and
 * the ramp discipline.  Param-settable via
 * --context-pool=off|shadow-only|combined.
 */
enum context_pool_mode context_pool_mode = CONTEXT_POOL_MODE_OFF;

/*
 * Translate the --strategy=NAME argument into a picker_mode_t.
 * Recognises the human-friendly aliases ("round-robin", "rr",
 * "bandit", "ucb1", "bandit-ucb1").  Returns false on unknown
 * input so the caller can emit a tidy error before exiting.
 */
bool parse_picker_mode(const char *name, enum picker_mode_t *out)
{
	if (name == NULL || out == NULL)
		return false;

	if (strcmp(name, "round-robin") == 0 ||
	    strcmp(name, "rr") == 0) {
		*out = PICKER_ROUND_ROBIN;
		return true;
	}
	if (strcmp(name, "bandit") == 0 ||
	    strcmp(name, "ucb1") == 0 ||
	    strcmp(name, "bandit-ucb1") == 0) {
		*out = PICKER_BANDIT_UCB1;
		return true;
	}
	return false;
}

const char *picker_mode_name(enum picker_mode_t mode)
{
	switch (mode) {
	case PICKER_ROUND_ROBIN:	return "round-robin";
	case PICKER_BANDIT_UCB1:	return "bandit-ucb1";
	}
	return "unknown";
}

const char *strategy_name(int arm)
{
	switch (arm) {
	case STRATEGY_HEURISTIC:		return "HEURISTIC";
	case STRATEGY_RANDOM:			return "RANDOM";
	case STRATEGY_COVERAGE_FRONTIER:	return "COVERAGE_FRONTIER";
	default:				return "?";
	}
}

bool is_strategy_eligible(int arm)
{
	if (arm < 0 || arm >= NR_STRATEGIES)
		return false;
	return true;
}

/*
 * Compute the dominant rescue class from the cumulative counters.
 * Returns RRC_NR_CLASSES (the "no amplification" sentinel) when no
 * class clears both the floor and the lead-over-second-best threshold.
 * Placeholder classes (RRC_UNUSUAL_FD_PRODUCER, RRC_WRONG_TYPE_FD,
 * RRC_PERSONA_GATED) are scanned so the comparison sees them, but the
 * classifier never credits a rescue to them today so they cannot win;
 * the orchestrator's bias dispatch treats them as plain RANDOM
 * regardless, which is also the behaviour for RRC_UNKNOWN.
 */
static enum random_rescue_class dominant_rescue_class(void)
{
	unsigned long best = 0;
	unsigned long second = 0;
	enum random_rescue_class best_class = RRC_NR_CLASSES;
	int i;

	for (i = 0; i < RRC_NR_CLASSES; i++) {
		unsigned long c = __atomic_load_n(
			&shm->random_rescue_class_count[i], __ATOMIC_RELAXED);
		if (c > best) {
			second = best;
			best = c;
			best_class = (enum random_rescue_class)i;
		} else if (c > second) {
			second = c;
		}
	}

	if (best < RRC_AMPLIFY_MIN_COUNT)
		return RRC_NR_CLASSES;
	if (best < second * RRC_AMPLIFY_LEAD_RATIO)
		return RRC_NR_CLASSES;
	return best_class;
}

/*
 * Map a dominant rescue class to the targeted intervention arm.
 * Defaults to STRATEGY_RANDOM (the historical pre-classifier
 * behaviour) for classes that do not have a structured replay
 * available -- placeholder classes whose underlying infrastructure
 * does not exist yet, the unknown bucket, and the "no class
 * dominant" sentinel.
 */
static int amplified_intervention_arm(enum random_rescue_class c)
{
	switch (c) {
	case RRC_COLD_SKIP:
		/* Heuristic with cold-skip suppressed -- the set_syscall_nr_
		 * heuristic read of plateau_rescue_amplified_class will
		 * short-circuit the kcov_syscall_cold_skip_pct retry while
		 * the intervention runs. */
		return STRATEGY_HEURISTIC;
	case RRC_CMP_DERIVED:
		/* Frontier-weighted picker.  RRC_CMP_DERIVED rescues fired
		 * on syscalls whose cmp_hints pool carried at least one
		 * learned constant, so the kernel is emitting comparison
		 * records the args generator could land but the per-syscall
		 * pick distribution is not steering to.  The frontier picker
		 * roulette-weights by per-syscall near-coverage signal,
		 * which is the closest structured proxy available for "this
		 * syscall is one new constant away from a fresh edge" --
		 * exactly the shape the cmp_rising_pc_flat hypothesis
		 * describes at the fleet level. */
		return STRATEGY_COVERAGE_FRONTIER;
	case RRC_UNUSUAL_FD_PRODUCER:
	case RRC_WRONG_TYPE_FD:
	case RRC_PERSONA_GATED:
	case RRC_UNKNOWN:
	case RRC_NR_CLASSES:
		break;
	}
	return STRATEGY_RANDOM;
}

static int select_plateau_intervention_strategy(
	enum strategy_selection_reason *reason_out)
{
	enum random_rescue_class amplified = RRC_NR_CLASSES;
	enum plateau_intervention_mode pim;
	unsigned long rot;
	int arm;

	/* Round-robin among the intervention modes.  The fetch_add
	 * returns the PREVIOUS counter value, so each rotation
	 * picks a mode cleanly without coordination between
	 * concurrent rotations -- the CAS in maybe_rotate_strategy
	 * already serialises which child runs select_next_strategy
	 * in the first place, but the fetch_add semantics keep the
	 * rotation correct even if a future refactor lets multiple
	 * writers in.
	 *
	 * The counter only ticks during plateau windows, so a
	 * fresh plateau picks up wherever the previous one left
	 * off rather than always starting from PIM_UNIFORM_RANDOM
	 * -- this matters when the plateau detector flaps between
	 * active and inactive across consecutive rotations and an
	 * always-from-zero counter would bias the early windows of
	 * each plateau toward the same mode. */
	rot = __atomic_fetch_add(
		&shm->plateau_intervention_rotation_counter, 1UL,
		__ATOMIC_RELAXED);
	pim = (enum plateau_intervention_mode)(rot % NR_PIM_MODES);

	/* Wall-lever shadow gate: refresh the eligibility
	 * set at every plateau-active rotation, BEFORE the mode-
	 * specific arm dispatch below, so the per-pick shadow probe
	 * in wall_lever_should_suppress_shadow always reads from a
	 * fleet-mean computed under the current rotation window
	 * regardless of which intervention mode is chosen.  The call
	 * is cheap (two O(MAX_NR_SYSCALL) walks, off the hot pick
	 * path) and the publish ordering rides on the same RELEASE-
	 * store of current_strategy that publishes the anti-prior
	 * weight table just below -- see the wall_lever_suppress
	 * comment in include/shm.h for the visibility contract. */
	wall_lever_refresh_baseline();

	/* Cold-ring deweight: PIM_COVERAGE_FRONTIER is a near-no-op
	 * when the per-syscall frontier rings have aged out everywhere
	 * (frontier_max_weight_cached == 0), the defining state of a
	 * deep plateau.  set_syscall_nr_coverage_frontier still drives
	 * forward via the silent-regime lifetime-ratio fallback, but
	 * a real run that re-plateaued after the rescue fired observed
	 * 9 childops self-demoting on "zero_edges" inside their canary
	 * window -- the rescue's PIM rotation pinned ~25% of windows
	 * on FRONTIER, the silent fallback found no new edges in the
	 * canary horizon, the canary gate demoted the ops, throughput
	 * collapsed to idle.  The rescue fired and did nothing.
	 *
	 * Substitute the cold FRONTIER slot with PIM_UNIFORM_RANDOM:
	 * it needs no populated ring, runs the historical pre-
	 * classifier baseline that does not feed the canary demote
	 * gate, and breaks the demote-to-idle spiral.  PIM_ANTI_PRIOR
	 * still occupies its own rotation slot, so each cold-ring
	 * cycle still hits both no-ring-needed modes (the cycle
	 * becomes UNIFORM:ANTI:RRC:UNIFORM-was-FRONTIER).
	 *
	 * Approach is skip-when-cold (single conditional substitution)
	 * rather than weight-to-zero (per-rotation NR_PIM_MODES
	 * remapping plus an active-modes mask).  Skip keeps the
	 * per-mode windows array, mode-name tables, and check-static
	 * gates stable -- substituting one enum value into another
	 * cell costs no new surface.  Weight-to-zero would add a
	 * second source of truth for "which modes are active" without
	 * changing steady-state behaviour.
	 *
	 * Threshold is == 0 (strict) rather than the picker's <= 2
	 * silent-regime threshold: at max_weight 1 or 2 the live
	 * regime still has a trickle of signal and we want FRONTIER
	 * to keep running on it.  Only the fully-aged-out case (no
	 * ratchet at all this rotation) gets the substitution.
	 *
	 * RELAXED load: the cache is itself updated RELAXED on every
	 * frontier_bump() and on each window-rotation recompute, and
	 * the picker reads it RELAXED, so an in-flight bump is
	 * acceptable here -- we read it once at the rotation boundary
	 * and either choice (skip or run) is safe and self-corrects
	 * on the next rotation when the cache settles.
	 *
	 * PIM_RRC_BIASED is deliberately NOT cold-deweighted: it can
	 * dispatch to FRONTIER via the RRC_CMP_DERIVED leg of
	 * amplified_intervention_arm(), but only when the classifier
	 * has accumulated positive evidence that the kernel is
	 * emitting comparison records the picker is not steering to.
	 * The cold ring does not contradict that signal -- a syscall
	 * with a populated cmp_hints pool and zero current frontier
	 * weight is exactly the case CMP_DERIVED amplification exists
	 * to escalate. */
	if (pim == PIM_COVERAGE_FRONTIER &&
	    __atomic_load_n(&shm->frontier_max_weight_cached,
			    __ATOMIC_RELAXED) == 0) {
		pim = PIM_UNIFORM_RANDOM;
		__atomic_fetch_add(
			&shm->stats.frontier.intervention_cold_skipped,
			1UL, __ATOMIC_RELAXED);
	}

	switch (pim) {
	case PIM_RRC_BIASED:
		/* Random-rescue classifier dispatch path.  Reuses
		 * the existing dominant_rescue_class +
		 * amplified_intervention_arm pair so the classifier-
		 * driven structured replay shape stays the same as
		 * when amplification was the only intervention mode;
		 * only the SCHEDULING of when it runs differs, not
		 * the internals. */
		amplified = dominant_rescue_class();
		arm = amplified_intervention_arm(amplified);
		break;
	case PIM_ANTI_PRIOR:
		/* Refresh the baseline at the rotation boundary so
		 * the per-call accept gate inside set_syscall_nr_
		 * random reads a value that matches the picker's
		 * CURRENT distribution.  Recomputing every rotation
		 * (rather than once-at-init) lets the bias track the
		 * learned distribution as it drifts across the run.
		 *
		 * STRATEGY_RANDOM is the arm regardless of mode -- the
		 * anti-prior bias rides per-call inside the random
		 * picker, not at the strategy-selection layer. */
		plateau_anti_prior_refresh_baseline();
		arm = STRATEGY_RANDOM;
		break;
	case PIM_COVERAGE_FRONTIER:
		/* Frontier-weighted picker, unconditional.  The
		 * bandit is short-circuited for the duration of the
		 * plateau, so without this rotation slot the
		 * coverage-frontier arm cannot be selected at all
		 * during a plateau window -- the exact windows where
		 * chasing near-coverage edges is most likely to
		 * unstick discovery.  No baseline refresh needed:
		 * the frontier picker reads its own per-syscall
		 * near-coverage ring on every pick. */
		arm = STRATEGY_COVERAGE_FRONTIER;
		break;
	case PIM_UNIFORM_RANDOM:
	default:
		/* Baseline mode: STRATEGY_RANDOM with no per-call
		 * bias.  Kept as a rotation slot so the A/B
		 * comparison has an anchor -- without it,
		 * "anti-prior helped" and "RRC-bias helped" both
		 * reduce to comparisons against each other rather
		 * than against the historical pre-classifier
		 * intervention shape. */
		arm = STRATEGY_RANDOM;
		break;
	}

	/* Publish the amplified class and intervention mode BEFORE
	 * the reason store on current_selection_reason in
	 * maybe_rotate_strategy.  The rotation site stores
	 * current_selection_reason with RELAXED ordering and pairs
	 * it with the current_strategy RELEASE store, so a child
	 * observing the new strategy also sees both freshly-
	 * published fields on its next pick.  RRC_NR_CLASSES means
	 * "no class dominant"; PIM_UNIFORM_RANDOM is published
	 * outside the intervention branch below so the anti-prior
	 * gate cannot stay latched on after the plateau lifts. */
	__atomic_store_n(&shm->plateau_rescue_amplified_class,
			 (int)amplified, __ATOMIC_RELAXED);
	__atomic_store_n(&shm->plateau_intervention_mode_current,
			 (int)pim, __ATOMIC_RELAXED);
	__atomic_fetch_add(
		&shm->plateau_intervention_mode_windows[pim], 1UL,
		__ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->stats.plateau_forced_windows, 1UL,
			   __ATOMIC_RELAXED);
	/* Side-channel count of intervention-forced frontier picks.
	 * Bumped here so both the unconditional PIM_COVERAGE_FRONTIER
	 * slot AND the PIM_RRC_BIASED dispatch that maps RRC_CMP_
	 * DERIVED to the frontier arm get attributed.  Deliberately
	 * NOT a bandit_pulls[STRATEGY_COVERAGE_FRONTIER] bump: D-UCB's
	 * exploration bonus assumes pulls reflect policy choice, not
	 * an intervention rescue, and folding the forced window into
	 * the learner's reward series would shift the arm's apparent
	 * yield toward the intervention cohort for the rest of the
	 * run. */
	if (arm == STRATEGY_COVERAGE_FRONTIER)
		__atomic_fetch_add(
			&shm->stats.frontier.intervention_pulls,
			1UL, __ATOMIC_RELAXED);
	*reason_out = SR_PLATEAU_FORCE;
	return arm;
}

int select_next_strategy(int prev,
			 enum strategy_selection_reason *reason_out)
{
	enum picker_mode_t mode;

	mode = __atomic_load_n(&shm->picker_mode, __ATOMIC_RELAXED);

	if (mode == PICKER_BANDIT_UCB1 &&
	    kcov_shm != NULL &&
	    __atomic_load_n(&kcov_shm->plateau_active, __ATOMIC_ACQUIRE))
		return select_plateau_intervention_strategy(reason_out);

	/* Not in a plateau intervention -- clear the amplification AND the
	 * mode so neither the RRC bias dispatch nor the anti-prior accept
	 * gate can stay latched on after the plateau lifts.  Both reset to
	 * the "no bias" sentinel (RRC_NR_CLASSES / PIM_UNIFORM_RANDOM)
	 * because their hot-path gates short-circuit cleanly on those
	 * values. */
	__atomic_store_n(&shm->plateau_rescue_amplified_class,
			 (int)RRC_NR_CLASSES, __ATOMIC_RELAXED);
	__atomic_store_n(&shm->plateau_intervention_mode_current,
			 (int)PIM_UNIFORM_RANDOM, __ATOMIC_RELAXED);

	return pick_next_strategy(prev, reason_out);
}

const char *strategy_selection_reason_name(enum strategy_selection_reason r)
{
	switch (r) {
	case SR_NORMAL_UCB:	return "NORMAL_UCB";
	case SR_ROUND_ROBIN:	return "ROUND_ROBIN";
	case SR_COLD_START:	return "COLD_START";
	case SR_PLATEAU_FORCE:	return "PLATEAU_FORCE";
	case NR_SELECTION_REASONS:	break;	/* sentinel */
	}
	return "?";
}
