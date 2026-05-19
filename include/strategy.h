#pragma once

#include <stdbool.h>

#include "syscall.h"		/* NR_GROUPS */

/*
 * Multi-strategy syscall-selection rotation.
 *
 * Each strategy implements a distinct pick_syscall policy.  Different
 * strategies have different blind spots; rotating through them surfaces
 * bug classes that any single policy systematically suppresses.
 *
 * The active strategy is fleet-wide (single shm-resident enum, every
 * child reads it on each syscall pick) and rotates every STRATEGY_WINDOW
 * ops.  The arm-selection policy itself is pluggable (see
 * enum picker_mode_t below): Phase 1 shipped a fixed round-robin;
 * Phase 2 adds a UCB1 bandit picker that consumes the per-strategy
 * edge-attribution counters as the reward signal.
 *
 * Per-strategy edge attribution is recorded in two parallel series --
 * shm->pc_edge_calls_by_strategy[] (calls that produced >=1 new edge)
 * and shm->pc_edge_count_by_strategy[] (real bucket-edge counts) --
 * so the operator can A/B compare strategies across many windows.
 * The bandit picker currently derives its reward signal from the
 * call-count series; the bucket-count series is recorded in parallel
 * so the alternative reward shape is visible without changing the
 * learner's behaviour.
 *
 * Today's arms are heuristic, uniform random, coverage-frontier, and
 * HEALER pair-bias (see enum strategy_t below); each becomes an arm
 * the bandit picker scores against the others.  Future arms under
 * consideration (group-saturation, newly-discovered, genetic) slot
 * into the same dispatch -- adding one is an enum entry plus a
 * pick_syscall hook.
 */

enum strategy_t {
	STRATEGY_HEURISTIC = 0,	/* default: group-bias + cold-skip + edgepair-bias */
	STRATEGY_RANDOM,	/* uniform pick, no biases */
	STRATEGY_COVERAGE_FRONTIER, /* roulette-wheel weighted by per-syscall
				     * frontier-edge count (see frontier_*
				     * APIs below) */
	STRATEGY_HEALER,	/* HEALER (SOSP'21): bias picks toward
				 * known-productive (predecessor -> succ)
				 * relations recorded by the Phase A
				 * observer.  Eligibility gated on either
				 * a meaningfully-populated pair table or
				 * a coverage-plateau signal. */
	NR_STRATEGIES,
};

/* Fleet-wide rotation boundary, in ops.  ~100 sec at 10K iter/sec. */
#define STRATEGY_WINDOW (1UL << 20)	/* 1,048,576 ops */

/*
 * How many rotation windows a CMP constant remains "seen" inside the
 * per-syscall novelty bloom before it decays back to "novel".  At ~100
 * sec/window this is ~13 minutes of fleet wall time, long enough that a
 * constant the kernel checks every few syscalls stays remembered, short
 * enough that a syscall whose validation surface drifts (e.g. after a
 * cgroup mount, a netns unshare, a new fd type entering the pool) gets
 * fresh novelty credit when its comparison constants change.
 */
#define CMP_NOVELTY_DECAY_WINDOWS 8

/*
 * Width of the per-syscall frontier-edge ring, in rotation windows.
 * The ring records, per slot, how many "first-time-this-window" PC edges
 * a syscall produced.  Sum across the ring is the syscall's recent
 * frontier-edge count, used by the coverage-frontier strategy as a
 * weight bias.  Mirrors CMP_NOVELTY_DECAY_WINDOWS so the two
 * coverage-novelty signals (CMP constants and PC edges) decay over the
 * same wall-clock horizon.
 */
#define FRONTIER_DECAY_WINDOWS 8

/*
 * Arm-selection policy used at each rotation boundary to decide which
 * strategy runs next.  Selected once at parse_args() time via the
 * --strategy flag, propagated into shm->picker_mode at init_shm time
 * so every child's CAS-winner observes the same value.
 */
enum picker_mode_t {
	PICKER_ROUND_ROBIN = 0,	/* Phase 1: (prev + 1) % NR_STRATEGIES */
	PICKER_BANDIT_UCB1,	/* Phase 2: UCB1 over per-arm reward */
};

/*
 * Why select_next_strategy() returned the arm it returned.  Stamped on
 * each window so the rotation site can tell a policy-chosen arm from an
 * intervention forced over the top of the picker, and so end-of-run
 * stats can report the two cohorts separately.
 *
 * SR_NORMAL_UCB:    UCB1 scored this arm highest among eligible arms.
 * SR_ROUND_ROBIN:   PICKER_ROUND_ROBIN cycled to this arm (or the
 *                   "everything ineligible" fallback ran).
 * SR_COLD_START:    UCB1 picked this arm because it had zero pulls and
 *                   the score formula is undefined until each arm has
 *                   been observed at least once.
 * SR_PLATEAU_FORCE: The plateau-intervention orchestrator overrode the
 *                   picker and forced this arm because kcov reports
 *                   edge discovery is stalled.  Windows with this
 *                   reason are NOT fed back into the UCB learner: a
 *                   forced-RANDOM intervention window is structurally
 *                   different from a policy-chosen RANDOM window
 *                   (every arm was stalled when this one ran), so
 *                   mixing them into bandit_pulls[]/bandit_reward_calls[]
 *                   contaminates the reward signal.
 */
enum strategy_selection_reason {
	SR_NORMAL_UCB = 0,
	SR_ROUND_ROBIN,
	SR_COLD_START,
	SR_PLATEAU_FORCE,
	NR_SELECTION_REASONS,	/* sentinel, must stay last */
};

/*
 * Random-rescue classifier.
 *
 * When the orchestrator forces STRATEGY_RANDOM during a coverage plateau
 * (SR_PLATEAU_FORCE) and that forced window's RANDOM picks produce new
 * edges, those edges are evidence that some structured bias the normal
 * picker imposes was filtering out a productive path.  The classifier
 * inspects the (predecessor, syscall) pair against the existing
 * heuristic / HEALER / cmp-hint state and assigns the rescue to the
 * narrowest category that explains why the structured path missed it.
 *
 * Counts accumulate in shm->random_rescue_class_count[] across all
 * intervention windows and the dominant class feeds back into the
 * orchestrator (see select_next_strategy) as a hint for which targeted
 * intervention to run next instead of plain RANDOM.
 *
 * Classes are checked in order; the FIRST matching class wins, so the
 * enum ordering encodes priority.  Classes whose detection requires
 * infrastructure that does not yet exist (persona / namespace
 * attribution, per-call fd-producer tracking) are defined here so the
 * orchestrator's bias dispatch covers the full surface even though the
 * classifier will not credit a rescue to them today; they sit as
 * placeholder buckets the future infrastructure can fill in without an
 * enum reorder.
 *
 * RRC_COLD_SKIP:           rec->nr would have been skipped under
 *                          STRATEGY_HEURISTIC's kcov cold-skip gate
 *                          (kcov_syscall_cold_skip_pct >= 50).
 * RRC_MISSING_PAIR:        the (immediate-pred -> rec->nr) cell in the
 *                          HEALER pair table has zero static prior AND
 *                          zero dynamic_hits -- a relation the
 *                          structured pickers cannot see at all.
 * RRC_UNSEEN_SUCCESSOR:    immediate-pred has hot outgoing pairs to
 *                          OTHER successors but this (pred, rec->nr) is
 *                          empty -- HEALER is investing in a different
 *                          branch from this predecessor.
 * RRC_STALE_PAIR:          (pred, rec->nr) has a non-zero static prior
 *                          but dynamic_hits has decayed to zero -- the
 *                          seed bootstrap saw the edge but the runtime
 *                          weight has rotted past HEALER's gate.
 * RRC_UNUSUAL_FD_PRODUCER: placeholder for per-call fd-source tracking;
 *                          today never selected by the classifier.
 * RRC_WRONG_TYPE_FD:       placeholder; typed-fd substitution gave a
 *                          wrong-class fd that worked.  Today never
 *                          selected by the classifier.
 * RRC_CMP_DERIVED:         this syscall has a non-empty cmp_hints pool,
 *                          so generate-args.c's 1-in-16 cmp_hints_try_get
 *                          path may have injected a learned constant that
 *                          carried the call past a kernel validation
 *                          check the structured pickers were not pushing
 *                          through.
 * RRC_PERSONA_GATED:       placeholder for namespace/cgroup/childop
 *                          persona attribution; persona infrastructure
 *                          does not exist yet, never selected today.
 * RRC_UNKNOWN:             rescue did not match any structured class.
 */
enum random_rescue_class {
	RRC_COLD_SKIP = 0,
	RRC_MISSING_PAIR,
	RRC_UNSEEN_SUCCESSOR,
	RRC_STALE_PAIR,
	RRC_UNUSUAL_FD_PRODUCER,
	RRC_WRONG_TYPE_FD,
	RRC_CMP_DERIVED,
	RRC_PERSONA_GATED,
	RRC_UNKNOWN,
	RRC_NR_CLASSES,		/* sentinel, must stay last */
};

/*
 * Plateau intervention mode.
 *
 * During a coverage plateau the orchestrator forces an arm over the top
 * of the bandit; without further structure that arm has been plain
 * STRATEGY_RANDOM (PIM_UNIFORM_RANDOM) or, once the random-rescue
 * classifier has accumulated evidence, a class-amplified replay
 * (PIM_RRC_BIASED, dispatched through dominant_rescue_class).  Both
 * modes leave one rescue avenue untouched: the bandit's learned priors
 * over per-syscall pick rate.  A learner that has converged on a
 * handful of "winning" syscalls keeps replaying them across the
 * intervention even when those wins are stale -- the priors themselves
 * are part of why the fleet is at plateau.
 *
 * PIM_ANTI_PRIOR is the complement: STRATEGY_RANDOM with a per-call
 * acceptance gate that INVERTS the learned per-syscall call-count
 * distribution.  Syscalls the bandit has been suppressing (low per-
 * syscall call count) get full acceptance; syscalls the bandit has
 * been over-picking (high count) get rejected at up to MAX_BOOST^-2 of
 * baseline acceptance.  The inversion is capped so a syscall stuck at
 * calls=0 (genuinely broken in this kernel, or simply never picked
 * before the plateau started) cannot 100x dominate the intervention.
 *
 * The orchestrator round-robins among the three modes at each rotation
 * boundary while the plateau is active, so the per-mode rescue yield is
 * directly comparable: each mode runs the same number of windows over
 * the lifetime of any plateau long enough for the rotation to cycle.
 * Anti-prior and RRC-biased modes are designed as complements --
 * anti-prior biases AWAY from the learned distribution, RRC-biased
 * biases TOWARD a specific failure class -- and both layer over the
 * UNIFORM_RANDOM baseline that makes the A/B shape interpretable.
 *
 * PIM_UNIFORM_RANDOM: STRATEGY_RANDOM with no per-call bias.  The
 *                     historical pre-classifier intervention shape;
 *                     kept as the third rotation slot to anchor the
 *                     comparison.
 * PIM_ANTI_PRIOR:     STRATEGY_RANDOM with the inverted-weight accept
 *                     gate active (see plateau_anti_prior_accept()).
 * PIM_RRC_BIASED:     dispatch via dominant_rescue_class() +
 *                     amplified_intervention_arm() -- HEALER / HEURISTIC
 *                     replay biased by the random-rescue classifier's
 *                     dominant class, or plain RANDOM when no class
 *                     dominates.
 */
enum plateau_intervention_mode {
	PIM_UNIFORM_RANDOM = 0,
	PIM_ANTI_PRIOR,
	PIM_RRC_BIASED,
	NR_PIM_MODES,		/* sentinel, must stay last */
};

/* Set by parse_args() before init_shm(). */
extern enum picker_mode_t picker_mode_arg;

/*
 * Parse a --strategy=NAME argument into a picker_mode_t.  Recognises
 * "round-robin"/"rr" and "bandit"/"ucb1"/"bandit-ucb1".  Returns false
 * on unknown input so the caller can emit an error and exit.
 */
bool parse_picker_mode(const char *name, enum picker_mode_t *out);

/* Human-readable name for the operator-facing log line. */
const char *picker_mode_name(enum picker_mode_t mode);

/*
 * Reward weight for the CMP-novelty secondary signal, expressed as
 * the integer reciprocal of 0.25.  Each novel CMP constant contributes
 * 1/CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL to the bandit's per-window
 * reward, so PC edges (weight 1.0) remain the dominant signal and
 * CMP variety acts as a tiebreaker / decay-resistor for arms whose
 * PC growth has plateaued but whose comparison surface is still
 * mutating.  Hard-coded today; future work may expose this via CLI.
 */
#define CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL 4

/*
 * Record the just-finished window's outcome for the bandit picker.
 * Always bumps the per-arm-per-reason buckets
 * bandit_pulls_by_reason[arm][reason] /
 * bandit_reward_calls_by_reason[arm][reason] /
 * bandit_reward_pc_edge_count_by_reason[arm][reason] so dump-side
 * analysis can split each arm's total exposure by selection path
 * (NORMAL_UCB vs COLD_START vs ROUND_ROBIN vs PLATEAU_FORCE).
 *
 * Updates to the LEARNER-facing series (bandit_pulls[],
 * bandit_reward_calls[], bandit_reward_pc_edge_count[], and the
 * discounted recent_pulls_x1000[] / recent_reward_x1000[] / EMA
 * decay) are gated on reason != SR_PLATEAU_FORCE.  A
 * forced-intervention window ran STRATEGY_RANDOM because every arm
 * was stalled, which is structurally different from "RANDOM scored
 * best under UCB"; folding the forced window into the learner's
 * history conflates the two cohorts and biases UCB toward RANDOM
 * for the rest of the run.  The by-reason buckets are diagnostic
 * (not consumed by the picker) so they capture every window
 * regardless of cohort -- the forced-cohort reward is exactly the
 * signal a future intervention classifier wants to see.
 *
 * For non-forced reasons, this bumps bandit_pulls[arm], adds
 * (pc_edge_calls + cmp_term) to bandit_reward_calls[arm], adds
 * pc_edge_count to bandit_reward_pc_edge_count[arm], and folds in
 * (cmp_new_constants / CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL) as a
 * secondary CMP-novelty term on the call-count reward only.
 *
 * pc_edge_calls is the per-window delta of pc_edge_calls_by_strategy
 * for the just-finished arm — calls that produced >=1 new edge.
 * pc_edge_count is the parallel per-window delta of
 * pc_edge_count_by_strategy — real bucket-edge bits flipped.  Both
 * series are recorded so the operator can see how the two reward
 * shapes would score the same windows without flipping the learner.
 *
 * Called from the CAS-winning child during maybe_rotate_strategy()
 * on every window close including SR_PLATEAU_FORCE windows; a
 * no-op when arm or reason is out of range.
 */
void bandit_record_pull(int arm, enum strategy_selection_reason reason,
			unsigned long pc_edge_calls,
			unsigned long pc_edge_count,
			unsigned long cmp_new_constants);

/*
 * Pick the arm to run during the next window using the configured
 * arm-selection POLICY only -- this is the raw UCB1 / round-robin
 * picker with no intervention layer.  In PICKER_ROUND_ROBIN mode this
 * is just (prev + 1) % NR_STRATEGIES; in PICKER_BANDIT_UCB1 mode this
 * runs the UCB1 score across all arms (any unpulled arm wins
 * immediately during cold-start).  Ineligible arms (per
 * is_strategy_eligible) are skipped in both the cold-start and
 * UCB1-score loops so the bandit only schedules an arm when its
 * preconditions are met.
 *
 * *reason_out is set to SR_ROUND_ROBIN, SR_COLD_START, or SR_NORMAL_UCB
 * depending on which path produced the winning arm.  Callers above the
 * intervention layer should call select_next_strategy() instead; this
 * raw picker is exposed so the orchestrator can delegate to it.
 */
int pick_next_strategy(int prev, enum strategy_selection_reason *reason_out);

/*
 * Select the arm to run during the next window, applying the plateau
 * intervention layer on top of the raw picker.  When PICKER_BANDIT_UCB1
 * is active and kcov reports the fleet is in a coverage plateau, this
 * returns STRATEGY_RANDOM with reason SR_PLATEAU_FORCE without
 * consulting the UCB1 scorer -- breaking out of whatever local minimum
 * the bandit has settled into.  Round-robin mode bypasses the
 * intervention (its own cycling already includes RANDOM, so forcing it
 * here would collapse the cycle).  In all other cases the call
 * delegates straight through to pick_next_strategy().
 *
 * This is the entry point the rotation site should call.  Splitting
 * the intervention layer above the picker keeps forced-intervention
 * windows out of the UCB learner's reward history -- see the
 * SR_PLATEAU_FORCE comment on enum strategy_selection_reason.
 */
int select_next_strategy(int prev,
			 enum strategy_selection_reason *reason_out);

/*
 * Human-readable name for a strategy_selection_reason, for the rotation
 * log line and the end-of-run dump.  Returns "?" for out-of-range
 * input (e.g. a wild shm write landing on the field).
 */
const char *strategy_selection_reason_name(enum strategy_selection_reason r);

/*
 * Coverage-plateau response: invoked by kcov_plateau_check() on the
 * rising-edge transition into PLATEAU state.  Resets
 * shm->syscalls_at_last_switch to 0 so the next maybe_rotate_strategy
 * call from any child trips the window boundary immediately, instead
 * of waiting up to STRATEGY_WINDOW (~1M ops, ~9 minutes at 2K iter/sec)
 * for the natural rotation cadence.  The CAS guard in
 * maybe_rotate_strategy still serialises the rotation work to one
 * child even though every child observes the trigger.
 *
 * This used to live alongside HEALER (the original consumer) but the
 * intervention is now picker-agnostic: select_next_strategy() above
 * the picker decides what to force based on plateau state.  Future
 * dispatches will replace the current "force STRATEGY_RANDOM" policy
 * with smarter interventions inside the orchestrator without touching
 * this trigger.
 */
void strategy_plateau_response(void);

/*
 * Per-arm eligibility check used by pick_next_strategy() to skip arms
 * whose preconditions are not yet met.  Arms without preconditions
 * return true unconditionally.  STRATEGY_HEALER is the first arm with
 * a real precondition; the readiness decision itself lives next to the
 * encoding it inspects -- see healer_strategy_ready() in healer.h --
 * and this function delegates after checking the operator-facing
 * no_healer kill switch.
 */
bool is_strategy_eligible(int arm);

/*
 * Human-readable arm name for the rotation log line so the operator can
 * see WHICH strategy the bandit just selected without cross-referencing
 * the enum.  Returns "?" for out-of-range input.
 */
const char *strategy_name(int arm);

/*
 * Walk a per-child KCOV_TRACE_CMP buffer and feed each interesting
 * comparison constant through the per-syscall novelty bloom in
 * shm->cmp_novelty[].  Constants that miss the bloom (and so are
 * "novel" within the last CMP_NOVELTY_DECAY_WINDOWS rotations) bump
 * shm->bandit_cmp_new_constants[strategy_at_pick] for the arm that
 * picked the syscall.  Called by every child from kcov_collect_cmp()
 * right after cmp_hints_collect; the bloom is a separate data
 * structure from the cmp_hints pool so the (deduplicated) hint pool
 * entries do not skew the novelty signal.
 *
 * Window-rotation count is read from shm->bandit_window_count, which
 * the rotation hook bumps once per completed window.
 *
 * is_explorer is true when the caller is one of the explorer-pool
 * children whose syscall picker forces STRATEGY_RANDOM independent of
 * the bandit's arm pick.  Their CMP novelty observations still feed
 * the per-syscall bloom (the bloom is a global "have we seen this
 * constant lately" signal that should not be polluted by the explorer
 * partition either way) but skip the per-arm reward attribution into
 * bandit_cmp_new_constants[]: explorers run a different strategy from
 * whatever the bandit picked for the bandit pool, so crediting their
 * CMP novelty to the bandit's current arm would be a misattribution.
 *
 * strategy_at_pick is the enum strategy_t snapshotted by
 * set_syscall_nr() into child->strategy_at_pick when the syscall was
 * picked.  Using the pick-time stamp rather than re-reading
 * shm->current_strategy here closes the rotation-mid-syscall window
 * where the strategy that picked the call differs from the strategy
 * current by the time the call returns -- without the stamp, long or
 * blocking syscalls routinely have their CMP novelty credited to the
 * wrong arm, contaminating the bandit's reward signal.  -1 sentinel
 * (and any other out-of-range value, e.g. from a wild shm write
 * landing on the field) skips attribution.
 */
void bandit_cmp_observe(unsigned long *trace_buf, unsigned int nr,
			bool is_explorer, int strategy_at_pick);

/*
 * Bump the per-syscall frontier-edge ring slot when kcov_collect
 * reports a NEW edge for syscall nr.  Called from kcov.c on the
 * found_new branch.  Out-of-range nr is silently dropped.
 *
 * "Frontier" here means an edge hit for the first time within the
 * current FRONTIER_DECAY_WINDOWS rotations: a syscall that keeps
 * producing first-time edges has unmined coverage worth re-exercising.
 */
void frontier_record_new_edge(unsigned int nr);

/*
 * Sum of the per-syscall frontier ring across all slots, capped to
 * a sensible u32.  O(1): the running sum is maintained in
 * shm->frontier_recent_count_cached[] -- producers bump the cache on
 * each new-edge add and frontier_window_advance() ages out the
 * outgoing slot's contribution -- so this is a single relaxed load.
 * Called by the coverage-frontier picker once per syscall slot during
 * the weighted-pick walk.
 */
unsigned long frontier_recent_count(unsigned int nr);

/*
 * Advance the frontier-edge ring to the next slot and zero it.  Called
 * exactly once per rotation by the CAS-winning child inside
 * maybe_rotate_strategy(), so plain (non-atomic) writes to the slot
 * index are safe.  The slot zero uses atomic stores because concurrent
 * kcov_collect callers may still be racing in.
 */
void frontier_window_advance(void);

/*
 * Classify a new-edge rescue produced during a SR_PLATEAU_FORCE window.
 * Walks the structured-picker state for (child->last_syscall_nr,
 * rec->nr) and returns the FIRST class whose precondition matches; the
 * caller bumps shm->random_rescue_class_count[class] so dump and
 * orchestrator amplification can read the cumulative distribution.
 *
 * Only meaningful when shm->current_selection_reason == SR_PLATEAU_FORCE
 * AND the call produced new edges -- the caller is responsible for both
 * gates.  Returns RRC_UNKNOWN if no class matched (a falling-through
 * rescue from the catch-all bucket).
 */
struct childdata;
struct syscallrecord;
enum random_rescue_class classify_random_rescue(struct syscallrecord *rec,
						struct childdata *child);

/*
 * Human-readable rescue-class name for the dump and the rotation log.
 * Returns "?" for out-of-range input.
 */
const char *random_rescue_class_name(enum random_rescue_class c);

/*
 * Hot-path gate for the per-class structured-replay biases inside the
 * heuristic picker (RRC_COLD_SKIP suppresses cold-skip) and arg
 * generation (RRC_CMP_DERIVED boosts cmp_hints injection rate).
 * Returns true only when the fleet is inside a SR_PLATEAU_FORCE
 * intervention window AND the orchestrator's published amplification
 * class matches the caller's expected class.  Both gates checked
 * because either alone is insufficient -- the amplification field can
 * carry a stale value briefly after the plateau clears (cleared on the
 * next non-intervention rotation) and the plateau_active flag alone
 * does not tell the bias site whether THIS class won.
 *
 * Cheap: three relaxed atomic loads and two comparisons; safe to call
 * on the hottest per-pick / per-arg paths.
 */
bool plateau_rescue_bias_active_for(enum random_rescue_class c);

/*
 * Hot-path gate for the anti-prior accept filter in set_syscall_nr_random.
 * Returns true only when the fleet is inside a SR_PLATEAU_FORCE
 * intervention window AND the orchestrator has rotated into the
 * PIM_ANTI_PRIOR mode for this window.  Same gating shape as
 * plateau_rescue_bias_active_for so the relaxed-load short-circuit
 * outside intervention windows costs one atomic load and one compare.
 */
bool plateau_anti_prior_active(void);

/*
 * Anti-prior accept gate.  Returns true iff the candidate clears a
 * rejection roll whose acceptance probability scales as
 * (baseline / clamp(calls, baseline/MAX_BOOST, MAX_BOOST*baseline)) /
 * MAX_BOOST -- low-count syscalls saturate at full uniform acceptance,
 * the median syscall accepts at 1/MAX_BOOST rate, and over-picked
 * syscalls bottom out at 1/MAX_BOOST^2.  The clamp / divide / cap
 * math is pre-computed per syscall by plateau_anti_prior_refresh_
 * baseline at every PIM_ANTI_PRIOR rotation; the hot path here reduces
 * to one relaxed load plus a single (rand() % SCALE) < weight roll.
 *
 * Returns true (pass) when baseline is zero, so the gate degenerates
 * gracefully to uniform pick before any window has refreshed the
 * cache (kcov_shm-unavailable falls under the same short-circuit
 * because refresh_baseline forces baseline=0 on that path).  Safe to
 * call without first checking plateau_anti_prior_active(); the caller
 * in set_syscall_nr_random goes through that gate to skip the per-call
 * load entirely outside an intervention.
 */
bool plateau_anti_prior_accept(unsigned int nr);

/*
 * Recompute and publish the anti-prior baseline -- the mean of
 * kcov_shm->per_syscall_calls across the full MAX_NR_SYSCALL slot
 * range -- and the matching per-syscall acceptance weight table
 * plateau_anti_prior_accept consumes.  Called by the orchestrator at
 * every rotation that selects PIM_ANTI_PRIOR so the bias targets the
 * picker's CURRENT distribution rather than a snapshot frozen at the
 * start of the run.  Cheap: two O(MAX_NR_SYSCALL) walks on the
 * rotation path (one for the baseline sum, one for the per-syscall
 * weight), never on the hot pick path.  Visibility of the weight
 * table is published by the RELEASE-store of current_strategy that
 * maybe_rotate_strategy emits after select_next_strategy returns;
 * see the weight-array comment in struct shm_s.
 */
void plateau_anti_prior_refresh_baseline(void);

/*
 * Human-readable name for the intervention mode, for the dump path and
 * the rotation log.  Returns "?" for out-of-range input.
 */
const char *plateau_intervention_mode_name(enum plateau_intervention_mode m);

/*
 * Plateau hypothesis machinery (Phase 1 -- diagnostics only).
 *
 * On the rising-edge transition into plateau_active the orchestrator
 * captures a snapshot of every counter the rule evaluator (Phase 2)
 * will need to classify WHY discovery has stalled.  A later periodic
 * tick computes the current snapshot, derives the per-counter delta
 * vs the entry snapshot, and feeds the delta into the rule evaluator.
 *
 * struct plateau_window_snapshot lives in shm-free memory -- the
 * entry snapshot is parent-private (only the parent walks the plateau
 * detector + rule check) and ride-along snapshots are stack-local on
 * the tick path.
 *
 * Field origins (all sourced from existing counters; no new wiring):
 *
 *   pc_edges     -- kcov_shm->edges_found.  Headline coverage signal,
 *                   the same counter the plateau detector itself
 *                   watches the rate of.
 *   cmp_unique   -- kcov_shm->cmp_hints_unique_inserts.  Counts CMP
 *                   records that survived bloom + pool dedup and
 *                   changed pool state -- the right denominator for
 *                   "how much unique CMP signal is the kernel still
 *                   emitting" while pc_edges has flattened.
 *   bandit_edges, explorer_edges -- shm->stats.{bandit,explorer}_pool_
 *                   edges_discovered.  Per-pool new-edge calls
 *                   attributed to the syscall path (excludes alt-op
 *                   childops).
 *   childop_edges_total -- sum of shm->stats.childop_edges_discovered[]
 *                   across enum child_op_type.  Per-alt-op edge
 *                   attribution -- bumped per alt-op invocation in the
 *                   post-call have_kcov block.
 *   remote_calls, total_calls -- kcov_shm->{remote,total}_calls.
 *                   KCOV_REMOTE_ENABLE share of the dispatch mix;
 *                   inline = total - remote.
 *   frontier_picks -- shm->stats.frontier_strategy_picks.  Calls that
 *                   went through the coverage-frontier roulette wheel.
 *   group_edges[NR_GROUPS] -- per-syscall-group sum of
 *                   kcov_shm->per_syscall_edges[], grouped by
 *                   syscalls[nr].entry->group.  Maps the call-count
 *                   new-edge signal onto the GROUP_* axis the
 *                   classifier needs for the single-group-dominant
 *                   rule.
 *
 * Captured at entry; deltas read at every tick.  Saturating-subtract
 * so a counter that wraps or briefly inverts (concurrent readers /
 * resets) produces 0 instead of UINT_MAX, which would otherwise blow
 * past every threshold in the rule evaluator.
 */
struct plateau_window_snapshot {
	unsigned long pc_edges;
	unsigned long cmp_unique;
	unsigned long bandit_edges;
	unsigned long explorer_edges;
	unsigned long childop_edges_total;
	unsigned long remote_calls;
	unsigned long total_calls;
	unsigned long frontier_picks;
	unsigned long group_edges[NR_GROUPS];
};

/*
 * Populate snap with a fresh read of every counter listed above.
 * Safe under concurrent writers -- every field is loaded RELAXED and
 * any cross-field inconsistency only matters to the saturating-
 * subtract in plateau_snapshot_delta below, which folds inversions
 * to zero.
 */
void plateau_snapshot_capture(struct plateau_window_snapshot *snap);

/*
 * Per-field delta out = now - entry, saturating to 0 on inversion.
 * Used by the rule evaluator (Phase 2) to score the deltas against
 * the conservative thresholds in each rule branch.
 */
void plateau_snapshot_delta(struct plateau_window_snapshot *out,
			    const struct plateau_window_snapshot *entry,
			    const struct plateau_window_snapshot *now);

/*
 * Plateau hypothesis classifier (Phase 1 -- diagnostics only).
 *
 * Each value names ONE hypothesis about why discovery has stalled.
 * The orchestrator does NOT yet act on the hypothesis -- when a rule
 * matches we only log which rule fired and bump a per-hypothesis fire
 * counter so the operator can see the cumulative distribution across
 * a long run.  The intervention layer (changing strategy, explorer
 * mix, remote-KCOV rate, cold-skip threshold in response to a fired
 * rule) is Phase 2 territory.
 *
 * Conservative thresholds throughout: each rule needs evidence that
 * would not show up in a healthy or short-lived plateau window.  See
 * strategy_plateau_hypothesis_check() in strategy.c for the exact
 * comparisons.
 *
 * Rules are checked in enum order and the FIRST match wins, so the
 * ordering encodes precedence -- CMP_RISING_PC_FLAT is the most
 * specific (we can see CMP signal still arriving while PC has gone
 * cold) and SINGLE_GROUP_DOMINANT is the most general (one group
 * accounting for >70% of edges is informative but compatible with
 * several finer-grained explanations).
 */
enum plateau_hypothesis {
	PLATEAU_HYPOTHESIS_NONE = 0,
	PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT,
	PLATEAU_HYPOTHESIS_CHILDOP_DOMINANT,
	PLATEAU_HYPOTHESIS_REMOTE_DOMINANT,
	PLATEAU_HYPOTHESIS_FRONTIER_COLD,
	PLATEAU_HYPOTHESIS_SINGLE_GROUP_DOMINANT,
	NR_PLATEAU_HYPOTHESES,	/* sentinel, must stay last */
};

/*
 * Human-readable name for a hypothesis enum value -- used in both the
 * stats_log_write() one-shot on hypothesis transitions and the
 * print_stats() per-tick visibility line.  Returns "?" for out-of-range
 * input (e.g. a wild write landing on a stored hypothesis field).
 */
const char *strategy_plateau_hypothesis_name(enum plateau_hypothesis h);

/*
 * Evaluate the rule tree against the (entry, now) delta.  Pure function
 * over the snapshot deltas -- no side effects, no logging, no counter
 * bumps.  Callers (print_stats below; future Phase 2 intervention
 * dispatcher) handle the bookkeeping and side effects.
 *
 * Returns PLATEAU_HYPOTHESIS_NONE when no rule matches the deltas;
 * this is the expected state for a freshly-entered plateau where
 * neither side of the window has accumulated enough samples for any
 * threshold to fire.
 */
enum plateau_hypothesis strategy_plateau_hypothesis_check(
		const struct plateau_window_snapshot *entry,
		const struct plateau_window_snapshot *now);

/*
 * Plateau-entry hook: capture the snapshot the rule evaluator will
 * diff against.  Idempotent within a single plateau episode -- the
 * entry snapshot is cleared when plateau_active drops, so the next
 * plateau gets a fresh baseline.  Called from strategy_plateau_
 * response() on the rising edge.
 */
void strategy_plateau_hypothesis_enter(void);

/*
 * Per-tick driver: if a plateau is in progress, compute the current
 * snapshot, run the rule evaluator, bump the per-hypothesis fire
 * counter on every transition into a non-NONE class (and once on the
 * matching transition into NONE so the stats line can show the rule
 * dropped out), and stash the deltas + result for the print_stats()
 * one-line block.  When plateau_active is false, drops the stashed
 * state so the print_stats block suppresses cleanly.
 *
 * Called from main.c print_stats() once per stats tick -- the
 * cadence matches the cadence the operator reads the periodic
 * dump at, so the hypothesis-transition log lines and the per-tick
 * visibility line stay in sync.
 */
void strategy_plateau_hypothesis_tick(void);

/*
 * Read-side accessors used by main.c print_stats() to format the
 * one-line plateau hypothesis block.  The deltas + last hypothesis +
 * fire-count array live as parent-private state in strategy.c (the
 * tick driver only runs on the parent path).
 */
enum plateau_hypothesis strategy_plateau_hypothesis_current(void);
const struct plateau_window_snapshot *strategy_plateau_hypothesis_delta(void);
unsigned long strategy_plateau_hypothesis_fires(enum plateau_hypothesis h);

/*
 * End-of-run summary: per-arm pulls + cumulative reward + mean
 * edges/window.  Called from dump_stats().
 */
void dump_strategy_stats(void);
