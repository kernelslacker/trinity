#pragma once

#include <stdbool.h>

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
 * Phase 1 ships two strategies (heuristic + uniform random); follow-up
 * commits add coverage-frontier, HEALER pair-bias, group-saturation,
 * newly-discovered, and genetic strategies (each becomes a new arm
 * the bandit picker can score against the existing ones).
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
 * Bumps bandit_pulls[arm], adds (pc_edge_calls + cmp_term) to
 * bandit_reward_calls[arm], adds pc_edge_count to
 * bandit_reward_pc_edge_count[arm], and folds in
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
 * Called from the CAS-winning child during maybe_rotate_strategy();
 * a no-op when arm is out of range.
 */
void bandit_record_pull(int arm,
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
 * a real precondition: it returns true once the pair-relation table
 * has accumulated at least HEALER_PICKER_PAIR_CELL_THRESHOLD cells with
 * weight > 1, OR when the coverage-plateau detector reports the fleet
 * is stalled (in which case the bandit benefits from any signal that
 * pushes it off the current local minimum, even one whose own data is
 * thin).  Cheap to call: bounded scan of the pair table with early-out.
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
 * a sensible u32.  Cheap O(FRONTIER_DECAY_WINDOWS) per call.  Called
 * by the coverage-frontier picker once per syscall slot during the
 * weighted-pick walk.
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
 * End-of-run summary: per-arm pulls + cumulative reward + mean
 * edges/window.  Called from dump_stats().
 */
void dump_strategy_stats(void);
