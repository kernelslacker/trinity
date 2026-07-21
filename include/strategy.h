#pragma once

#include <stdbool.h>

#include "syscall.h"		/* NR_GROUPS */

/*
 * Multi-strategy syscall-selection rotation.  Fleet-wide strategy enum
 * rotates every STRATEGY_WINDOW ops; the arm-selection policy is
 * pluggable (see enum picker_mode_t below).
 * See Documentation/strategy.md for the design rationale.
 */

enum strategy_t {
	STRATEGY_HEURISTIC = 0,	/* default: group-bias + cold-skip */
	STRATEGY_RANDOM,	/* uniform pick, no biases */
	STRATEGY_COVERAGE_FRONTIER, /* roulette-wheel weighted by per-syscall
				     * frontier-edge count (see frontier_*
				     * APIs below) */
	NR_STRATEGIES,
};

/* Fleet-wide rotation boundary, in ops.  ~5 min at ~450 ops/sec; tune
 * down if observed fleet rate is lower so cold-start completes inside
 * a typical run. */
#define STRATEGY_WINDOW (1UL << 17)	/* 131,072 ops */

/* Tightened rotation boundary used only while kcov_shm->plateau_active
 * is set.  ~8x more rotations than STRATEGY_WINDOW so the plateau-
 * intervention layer (SR_PLATEAU_FORCE, RRC-biased replay, anti-prior
 * accept gating) gets re-applied many times inside one 600s detector
 * window instead of ~1.6 times.  A real run that re-plateaued after
 * the detector fired showed 4 edges/600s -- the bandit was stuck in a
 * local minimum because the rescue cadence was wider than the detector
 * window.  Healthy-run cadence stays at STRATEGY_WINDOW. */
#define PLATEAU_STRATEGY_WINDOW (1UL << 14)	/* 16,384 ops */

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
 * Silent-streak SHADOW threshold for the coverage-frontier picker.
 * SHADOW-only: not read by any picker accept/retry / scoring / weight
 * math -- adjusting the value cannot perturb the live frontier
 * distribution.
 * See Documentation/strategy.md for the design rationale.
 */
#define FRONTIER_SHADOW_DECAY_STREAK 64UL

/*
 * Per-syscall LIVE-regime miss-streak cooldown threshold (shadow).
 * SHADOW-only: not read by any picker accept/retry / scoring / weight
 * math -- adjusting the value cannot perturb the live frontier
 * distribution.
 * See Documentation/strategy.md for the design rationale.
 */
#define FRONTIER_LIVE_MISS_COOLDOWN 4UL

/*
 * Silent-streak decay live-reject denom (Arm B only).  Companion to the
 * shadow predicate gated on FRONTIER_SHADOW_DECAY_STREAK + the no-CMP-
 * and-no-SUCCESS-errno-shift UNLESS clause.  REJECT_DENOM-1 / REJECT_DENOM
 * (31/32 == ~96.875% rejection) matches FRONTIER_ERRNO_PLATEAU_REJECT_DENOM
 * and CRED_THROTTLE_REJECT_DENOM so an Arm-B child still samples a
 * decay-classified syscall at ~3% -- any of the four lanes the silent
 * streak resets on (PC-edge novelty, transition novelty, CMP novelty,
 * SUCCESS-errno shift) will release the decay on the very next pick that
 * observes the productive event.
 */
#define FRONTIER_SILENT_DECAY_REJECT_DENOM 32U

/*
 * LIVE-regime probabilistic pick-reject denom (blanket safe
 * down-payment).  Fires unconditionally on every LIVE-regime pick with
 * 1 / REJECT_DENOM probability.  Denominator matches
 * FRONTIER_SILENT_DECAY_REJECT_DENOM / FRONTIER_ERRNO_PLATEAU_REJECT_
 * DENOM / CRED_THROTTLE_REJECT_DENOM so the three live-rejection gates
 * share one tunable shape.
 * See Documentation/strategy.md for the design rationale.
 */
#define FRONTIER_LIVE_DECAY_REJECT_DENOM 32U

/*
 * Errno-plateau decay predicate constants for the coverage-frontier
 * picker's silent-regime accept path.  Classifies a lifetime-call
 * >= MIN_CALLS syscall with zero edges/transitions/CMP inserts whose
 * returns are dominated by one non-SUCCESS errno bucket as wasting
 * silent-regime picks.  Credential-class syscalls are excluded (they
 * have their own cred_throttle gate) so no syscall is decayed twice.
 * See Documentation/strategy.md for the design rationale.
 */
#define FRONTIER_ERRNO_PLATEAU_MIN_CALLS 512UL
#define FRONTIER_ERRNO_PLATEAU_DOM_PCT 90U
#define FRONTIER_ERRNO_PLATEAU_REJECT_DENOM 32U

/*
 * Saturation-cooldown predicate magnitude gate.  Syscalls with fewer
 * than this many accumulated lifetime picks are spared from the
 * cooldown regardless of plateau / spare-lane outcomes.
 * See Documentation/strategy.md for the design rationale.
 */
#define FRONTIER_SATCOOL_CMIN 10000UL

/*
 * Saturation-cooldown mode (--frontier-saturation-cooldown).
 * OFF | SHADOW_ONLY | COMBINED ramp; SHADOW_ONLY and COMBINED are both
 * shadow-only today (predicate evaluates + counters bump, live
 * selection unchanged).  OFF is byte-identical to a build before this
 * knob existed.
 * See Documentation/strategy.md for the design rationale.
 */
enum frontier_saturation_cooldown_mode {
	FRONTIER_SATURATION_COOLDOWN_MODE_OFF = 0,
	FRONTIER_SATURATION_COOLDOWN_MODE_SHADOW_ONLY = 1,
	FRONTIER_SATURATION_COOLDOWN_MODE_COMBINED = 2,
};

extern enum frontier_saturation_cooldown_mode frontier_saturation_cooldown_mode;

/*
 * Spare-cascade classification shared by the silent-regime and LIVE-
 * regime cooldown helpers below and by the shadow attribution-
 * confidence dump in stats/dump.c.  Returns the FIRST matching spare
 * reason under the same lane order (windowed-edges > arggen >
 * ret_objtype producer > none), so a diagnostic reader can bucket a
 * syscall's clean/noisy ratio by why it survives cooldown.  Cheap: one
 * RELAXED load on each of frontier_recent_count / per_syscall_cmp_
 * inserts / per_syscall_errno[SUCCESS] / per-arch producer bitmap.  No
 * side effects -- unlike the _spare helpers below the classifier bumps
 * no shadow counters, so it stays safe to call from the dump loop.
 */
enum frontier_spare_reason {
	FRONTIER_SPARE_NONE = 0,
	FRONTIER_SPARE_WINDOWED_EDGES,
	FRONTIER_SPARE_ARGGEN,
	FRONTIER_SPARE_OBJPRODUCER,
};

enum frontier_spare_reason
frontier_spare_lane_decide(unsigned int syscallnr, bool do32);

/*
 * Saturation-cooldown spare-lane helper, extracted from the silent-
 * regime accept site in random-syscall.c so the predicate, the per-
 * arch producer-observer bitmap, and the shadow-counter bumps live in
 * one place.  No-op when frontier_saturation_cooldown_mode is OFF or
 * kcov_shm is unavailable; otherwise evaluates the windowed-plateau +
 * magnitude predicate and bumps the frontier_satcool_* shadow
 * counters.  SHADOW-ONLY -- never returns a value, never gates picker
 * selection; the COMBINED live-reject is a deliberate follow-up.
 * See the implementation in strategy-frontier.c for the full contract.
 */
void frontier_satcool_spare(unsigned int syscallnr, bool do32);

/*
 * LIVE-regime cooldown discriminator magnitude floor.  Sibling of
 * FRONTIER_SATCOOL_CMIN but deliberately much smaller so productive
 * syscalls below the satcool 10000 mark stay spare-eligible.
 * See Documentation/strategy.md for the design rationale.
 */
#define FRONTIER_LIVE_COOL_CMIN 256UL

/*
 * LIVE-regime cooldown discriminator mode
 * (--frontier-live-cooldown-mode).  OFF | SHADOW_ONLY | COMBINED ramp;
 * SHADOW_ONLY and COMBINED are both shadow-only today (discriminator
 * evaluates + counters bump, live cooldown decision unchanged).  OFF
 * is byte-identical to a build before this knob existed.  Independent
 * of the LIVE-regime rotation-loop halving in
 * frontier_window_advance(), which is always on.
 * See Documentation/strategy.md for the design rationale.
 */
enum frontier_live_cooldown_mode {
	FRONTIER_LIVE_COOLDOWN_MODE_OFF = 0,
	FRONTIER_LIVE_COOLDOWN_MODE_SHADOW_ONLY = 1,
	FRONTIER_LIVE_COOLDOWN_MODE_COMBINED = 2,
};

extern enum frontier_live_cooldown_mode frontier_live_cooldown_mode;

/*
 * LIVE-regime cooldown spare-lane helper, sibling of
 * frontier_satcool_spare above.  Shares the predicate body (windowed-
 * edges plateau spare, distinct-CMP / first-success-TRANSITION arggen
 * spare, ret_objtype producer-observer spare) and the per-arch
 * producer-observer bitmap; differs in the outer gate (live mode), the
 * magnitude floor (FRONTIER_LIVE_COOL_CMIN, NOT FRONTIER_SATCOOL_CMIN
 * -- see the FRONTIER_LIVE_COOL_CMIN comment for the rationale), and
 * the shadow counter family the bumps land in (frontier_live_cool_*).
 * No-op when frontier_live_cooldown_mode is OFF or kcov_shm is
 * unavailable; SHADOW-ONLY -- never returns a value, never gates picker
 * selection; the COMBINED live divergence is a deliberate follow-up.
 * Called from the LIVE-regime miss-attribution path in random-syscall.c
 * (account_per_syscall_new_edges) immediately after the existing
 * frontier_live_would_skip projection so the discriminated counters
 * sit alongside the undiscriminated projection for direct comparison.
 * See the implementation in strategy-frontier.c for the full contract.
 */
void frontier_live_cool_spare(unsigned int syscallnr, bool do32);

/*
 * Floored-barren sub-floor demote thresholds.  The predicate targets
 * pure zero-arg getters whose lifetime PC-edge yield has plateaued to
 * a hard floor: num_args == 0, no object producer (ret_objtype ==
 * OBJ_NONE), no sanitiser (state-mutators like munlockall / setsid /
 * sched_yield are excluded and left to the softer sibling plateau
 * decay), reach <= FRONTIER_BARREN_MAX_REACH, calls > FRONTIER_BARREN_
 * C_MIN, and both lifetime and windowed edges == 0.
 *
 * FRONTIER_BARREN_C_MIN is deliberately much smaller than the
 * FRONTIER_SATCOOL_CMIN 10000 floor: the barren predicate needs less
 * evidence to conclude "hard-floored" precisely because the vetted
 * skeleton (zero args, no producer, no mutator, low reach) already
 * excludes the syscalls whose payoff is delayed or off-path.
 * FRONTIER_BARREN_MAX_REACH caps the predicate to slots whose
 * lifetime edge yield is genuinely marginal; a slot past that reach
 * has earned its productivity and is left to the reach-band picker.
 * FRONTIER_BARREN_DEMOTE_MULT is the sub-floor denominator multiplier
 * a COMBINED live variant would apply -- accept probability drops
 * from (w + 1) / (SCALE + 1) to (w + 1) / (SCALE * M + 1), keeping a
 * residual sample rather than starving the slot; only a real PC-edge
 * or transition resets the underlying signals.
 */
#define FRONTIER_BARREN_C_MIN         2500UL
#define FRONTIER_BARREN_MAX_REACH     16UL
#define FRONTIER_BARREN_DEMOTE_MULT   16UL

/*
 * Floored-barren sub-floor demote mode
 * (--frontier-barren-demote).  OFF | SHADOW_ONLY | COMBINED ramp;
 * SHADOW_ONLY and COMBINED are both shadow-only today (predicate
 * evaluates + counters bump, live selection unchanged).  OFF is
 * byte-identical to a build before this knob existed.
 * See Documentation/strategy.md for the design rationale.
 */
enum frontier_barren_demote_mode {
	FRONTIER_BARREN_DEMOTE_MODE_OFF = 0,
	FRONTIER_BARREN_DEMOTE_MODE_SHADOW_ONLY = 1,
	FRONTIER_BARREN_DEMOTE_MODE_COMBINED = 2,
};

extern enum frontier_barren_demote_mode frontier_barren_demote_mode;

/*
 * Floored-barren sub-floor demote helper.  Sibling of
 * frontier_satcool_spare / frontier_live_cool_spare above; targets
 * the pure zero-arg getter set whose lifetime PC-edge yield has
 * plateaued to a hard floor and whose vetted skeleton (num_args == 0
 * AND ret_objtype == OBJ_NONE AND sanitise == NULL AND reach <=
 * FRONTIER_BARREN_MAX_REACH) already excludes the object-producer,
 * state-mutator, and heuristic-arm-spike sets that the softer plateau
 * decay owns.  No-op when frontier_barren_demote_mode is OFF or
 * kcov_shm is unavailable; SHADOW-ONLY -- never returns a value,
 * never gates picker selection; the COMBINED sub-floor live divergence
 * is a deliberate follow-up.  Called from the silent-regime accept
 * site in random-syscall.c immediately after frontier_satcool_spare
 * so the two shadow projections sit alongside each other.
 */
void frontier_barren_demote(unsigned int syscallnr, bool do32);

/*
 * Heuristic-arm group-bias anti-lock-in damper -- F-RSEQ.
 * (--frontier-group-antilock).  OFF | SHADOW_ONLY | COMBINED ramp;
 * SHADOW_ONLY and COMBINED are both shadow-only today (predicate
 * evaluates + counters bump, live selection unchanged).  OFF is
 * byte-identical to a build before this knob existed.
 * See Documentation/strategy.md for the design rationale, discriminator
 * shape, state keying, and dispatch-tail bookkeeping order.
 */
enum frontier_group_antilock_mode {
	FRONTIER_GROUP_ANTILOCK_MODE_OFF = 0,
	FRONTIER_GROUP_ANTILOCK_MODE_SHADOW_ONLY = 1,
	FRONTIER_GROUP_ANTILOCK_MODE_COMBINED = 2,
};

extern enum frontier_group_antilock_mode frontier_group_antilock_mode;

/*
 * Cost-pool one-shot selector mode (--cost-pool-selector).
 * OFF | SHADOW_ONLY | COMBINED ramp; SHADOW_ONLY and COMBINED are
 * both shadow-only today (observer accumulates, live pick stays flat
 * draw-then-reject).  OFF is byte-identical to a build before this
 * knob existed.  The shadow observer consumes ZERO rnd_u32() calls so
 * it cannot perturb the live pick stream under any mode.
 * See Documentation/strategy.md for the design rationale and the
 * coin-then-draw closed form.
 */
enum cost_pool_selector_mode {
	COST_POOL_SELECTOR_MODE_OFF = 0,
	COST_POOL_SELECTOR_MODE_SHADOW_ONLY = 1,
	COST_POOL_SELECTOR_MODE_COMBINED = 2,
};

extern enum cost_pool_selector_mode cost_pool_selector_mode;

/*
 * Context-pool mode -- Path-A regular_suppressed shadow instrumentation
 * for the picker (--context-pool).  OFF | SHADOW_ONLY | COMBINED ramp;
 * SHADOW_ONLY and COMBINED are both shadow-only today (classifier
 * evaluates + counters bump, live pool membership unchanged).  OFF is
 * byte-identical to a build before this knob existed.
 * See Documentation/strategy.md for the design rationale.
 */
enum context_pool_mode {
	CONTEXT_POOL_MODE_OFF = 0,
	CONTEXT_POOL_MODE_SHADOW_ONLY = 1,
	CONTEXT_POOL_MODE_COMBINED = 2,
};

extern enum context_pool_mode context_pool_mode;

/*
 * Magnitude floor for the regular_suppressed classifier.  Sized on the
 * same rationale as FRONTIER_LIVE_COOL_CMIN above: the productive
 * syscalls the classifier MUST NOT mis-suppress sit far below the
 * satcool 10000 mark, so reusing FRONTIER_SATCOOL_CMIN would leave the
 * measured EPERM hogs (fchown / cred family etc.) under-floor and never
 * classified; but a syscall with only a handful of picks must not
 * qualify on a statistically-meaningless sample.  256 admits the
 * measured hogs while keeping the sample-size bar high enough that a
 * fresh-run tail cannot spuriously classify.  A/B-tunable from the
 * SHADOW_ONLY context_regular_suppressed_would_skip_per_syscall[]
 * readout once that runs.
 */
#define CONTEXT_REGULAR_SUPPRESSED_CMIN 256UL

/*
 * EPERM-rate threshold (percent of total kernel-visible calls) required
 * before a syscall is classified regular_suppressed.  The spec's
 * "regular EPERM-rate ~= 100%" gate is expressed as a percentage so the
 * eventual tweak is a single integer, and 90 matches the sibling
 * CRED_THROTTLE_HARD_FAIL_PCT convention (see include/cred_throttle.h)
 * -- calibrated to the same "provably impossible" evidence bar the
 * cred oracle already uses.  The success == 0 AND edges == 0 clauses
 * are strict rather than percentage-gated because a single first-
 * success TRANSITION or first-edge event is a hard disproof of the
 * "regular-dead" classification.
 */
#define CONTEXT_REGULAR_SUPPRESSED_EPERM_PCT 90UL

/*
 * Path-A regular_suppressed classifier + shadow bump.  Called from the
 * pick-finalise site in random_syscall/pickers.c (both HEURISTIC and
 * RANDOM arms) after every gate has passed and the pick is about to be
 * published, alongside the cost_pool_selector_live_note attribution so
 * the shadow projection and the live finalise cadence stay in lock-
 * step.  No-op when context_pool_mode is OFF or kcov_shm is unavailable;
 * SHADOW-ONLY -- never returns a value, never gates picker selection.
 * The COMBINED live suppression is a deliberate follow-up after the
 * classifier is validated against a real run.  See the implementation
 * in strategy-frontier.c for the full contract.
 */
void context_regular_suppressed_shadow(unsigned int syscallnr, bool do32);

/*
 * Group-pin anti-lock-in damper thresholds.  A pin needs at least
 * MIN_STREAK heuristic picks before release-eligibility; the
 * watermark gap must then exceed COV_WINDOW before the pin counts
 * as stale.
 * See Documentation/strategy.md for the design rationale.
 */
#define FRONTIER_FRSEQ_MIN_STREAK 32U
#define FRONTIER_FRSEQ_COV_WINDOW 24U

/*
 * Errno-plateau decay predicate.  Returns true when syscall nr (under
 * the do32 arch table) matches the wasteful-silent-pick shape described
 * above the FRONTIER_ERRNO_PLATEAU_* constants.  Called from the
 * coverage-frontier picker's silent-regime accept path; the SHADOW
 * counters (frontier_errno_decay_*) are bumped at the call site for
 * both A/B arms in lock-step, and the per-child stamp
 * (child->frontier_errno_decay_arm_b) drives the live REJECT_DENOM-1 /
 * REJECT_DENOM probabilistic rejection only in Arm B.
 *
 * Returns false when kcov_shm is unavailable so the picker degrades to
 * the historical accept distribution rather than wedging on a NULL
 * deref -- matches the kcov-less fallback the rest of the codebase
 * already takes.
 */
bool frontier_errno_plateau_should_decay(unsigned int nr, bool do32);

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
 * each window so the rotation site can tell a policy-chosen arm from
 * an intervention forced over the top of the picker.  Invariant:
 * SR_PLATEAU_FORCE windows are NOT fed back into the UCB learner
 * (forced-RANDOM is structurally distinct from policy-chosen RANDOM).
 * See Documentation/strategy.md for the design rationale.
 */
enum strategy_selection_reason {
	SR_NORMAL_UCB = 0,
	SR_ROUND_ROBIN,
	SR_COLD_START,
	SR_PLATEAU_FORCE,
	NR_SELECTION_REASONS,	/* sentinel, must stay last */
};

/*
 * Random-rescue classifier.  Categorises which structured-bias
 * blind-spot each SR_PLATEAU_FORCE rescue exploited so the
 * orchestrator can amplify the matching class on later interventions.
 * Invariant: classes are checked in enum order; the FIRST match wins,
 * so ordering encodes priority.  Currently attributed today:
 * RRC_COLD_SKIP, RRC_CMP_DERIVED, RRC_UNKNOWN (catch-all); the others
 * are placeholder buckets for future attribution infrastructure.
 * See Documentation/strategy.md for the design rationale and the
 * per-class detection preconditions.
 */
enum random_rescue_class {
	RRC_COLD_SKIP = 0,
	RRC_UNUSUAL_FD_PRODUCER,
	RRC_WRONG_TYPE_FD,
	RRC_CMP_DERIVED,
	RRC_PERSONA_GATED,
	RRC_UNKNOWN,
	RRC_NR_CLASSES,		/* sentinel, must stay last */
};

/*
 * Plateau intervention mode.  The orchestrator round-robins among
 * these four modes at each rotation boundary while the plateau is
 * active, so per-mode rescue yield is directly comparable.  Invariant:
 * intervention windows short-circuit the bandit layer entirely, so
 * the frontier arm is only reachable during a plateau via
 * PIM_COVERAGE_FRONTIER or the RRC-biased amplification path.
 * See Documentation/strategy.md for the design rationale and per-mode
 * dispatch shape.
 */
enum plateau_intervention_mode {
	PIM_UNIFORM_RANDOM = 0,
	PIM_ANTI_PRIOR,
	PIM_RRC_BIASED,
	PIM_COVERAGE_FRONTIER,
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
 * Reward-weight integer reciprocals for the bandit's two secondary
 * signals.  Each novel CMP constant contributes 1/CMP_BANDIT_REWARD_
 * WEIGHT_RECIPROCAL and each edge-count point contributes
 * 1/EDGE_COUNT_BANDIT_REWARD_WEIGHT_RECIPROCAL to the per-window
 * reward, so PC-edge call count (weight 1.0) stays dominant and the
 * secondaries only tie-break.  Hard-coded for the initial shadow ramp.
 * See Documentation/strategy.md for the design rationale.
 */
#define CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL 4
#define EDGE_COUNT_BANDIT_REWARD_WEIGHT_RECIPROCAL 8

/*
 * Blended-reward mode (--bandit-reward-edge-count).
 * OFF | SHADOW_ONLY | COMBINED ramp.  OFF and SHADOW_ONLY leave the
 * learner-facing reward total byte-identical to today; COMBINED folds
 * the weighted edge-count term into bandit_reward_calls[].
 * Invariant: SR_PLATEAU_FORCE windows short-circuit the learner
 * update in bandit_record_pull() and the edge-count term goes through
 * the same gate, so forced-intervention windows never fold into the
 * learner even under COMBINED.
 * See Documentation/strategy.md for the design rationale.
 */
enum bandit_reward_edge_count_mode {
	BANDIT_REWARD_EDGE_COUNT_OFF = 0,
	BANDIT_REWARD_EDGE_COUNT_SHADOW_ONLY = 1,
	BANDIT_REWARD_EDGE_COUNT_COMBINED = 2,
};

extern enum bandit_reward_edge_count_mode bandit_reward_edge_count_mode;

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
 * For non-forced reasons, this bumps bandit_pulls[arm], adds the
 * learner reward pc_edge_calls + cmp_term to bandit_reward_calls[arm],
 * adds pc_edge_count to bandit_reward_pc_edge_count[arm], and folds in
 * (cmp_new_constants / CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL) as a
 * secondary CMP-novelty term on the call-count reward only.
 *
 * pc_edge_calls is the per-window delta of pc_edge_calls_by_strategy
 * for the just-finished arm — calls that produced >=1 new edge.
 * pc_edge_count is the parallel per-window delta of
 * pc_edge_count_by_strategy — real bucket-edge bits flipped.  Both
 * series are recorded so the operator can compare the call-count and
 * bucket-count reward shapes across the same windows.
 *
 * Called from the CAS-winning child during maybe_rotate_strategy()
 * on every window close including SR_PLATEAU_FORCE windows; a
 * no-op when arm or reason is out of range.
 */
void bandit_record_pull(int arm, enum strategy_selection_reason reason,
			unsigned long pc_edge_calls,
			unsigned long pc_edge_count,
			unsigned long cmp_new_constants,
			unsigned long warn_fires,
			bool was_chaos);

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
 * The intervention is picker-agnostic: select_next_strategy() above
 * the picker decides what to force based on plateau state.  Future
 * dispatches will replace the current "force STRATEGY_RANDOM" policy
 * with smarter interventions inside the orchestrator without touching
 * this trigger.
 */
void strategy_plateau_response(void);

/*
 * Per-arm eligibility check used by pick_next_strategy() to skip arms
 * whose preconditions are not yet met.  No arm has a precondition
 * today; the hook stays in case a future arm needs one.
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
 *
 * Returns the number of bloom-novel KCOV_CMP_CONST constants observed
 * on this call (sum over all records in trace_buf).  The return value
 * is independent of is_explorer / strategy_at_pick -- those only gate
 * the per-arm bandit_cmp_new_constants[] attribution -- so callers can
 * use a positive return to trigger CMP-source corpus saves even for
 * explorer-pool children or pre-first-pick syscalls.  Returns 0 if
 * trace_buf is NULL, nr is out of range, the buffer is empty, or no
 * compile-time-constant record exercised a never-before-seen value.
 */
unsigned long bandit_cmp_observe(unsigned long *trace_buf, unsigned int nr,
				bool do32, bool is_explorer,
				int strategy_at_pick);

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
 * Walks the structured-picker state for
 * (child->bug_backtrace.last_syscall_nr, rec->nr) and returns the FIRST
 * class whose precondition matches; the
 * caller bumps shm->random_rescue_class_count[class] so dump and
 * orchestrator amplification can read the cumulative distribution.
 *
 * cold_skip_pct_before is the value of kcov_syscall_cold_skip_pct(rec->nr)
 * sampled by the caller BEFORE kcov_collect ran -- a new-edge call warms
 * last_edge_at[nr] inside kcov_collect, so by the time the classifier
 * runs the live reading is zero and RRC_COLD_SKIP would never trip for
 * exactly the cold-syscall rescues this classifier exists to surface.
 *
 * Only meaningful when shm->current_selection_reason == SR_PLATEAU_FORCE
 * AND the call produced new edges -- the caller is responsible for both
 * gates.  Returns RRC_UNKNOWN if no class matched (a falling-through
 * rescue from the catch-all bucket).
 */
struct childdata;
struct syscallrecord;
enum random_rescue_class classify_random_rescue(struct syscallrecord *rec,
						struct childdata *child,
						unsigned int cold_skip_pct_before);

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
 * to one relaxed load plus a single rnd_modulo_u32(SCALE) < weight roll.
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
 * kcov_shm->per_syscall.per_syscall_calls across the currently-active syscall
 * set (biarch: nr_active_32bit_syscalls + nr_active_64bit_syscalls;
 * uniarch: nr_active_syscalls) -- and the matching per-syscall
 * acceptance weight table plateau_anti_prior_accept consumes.
 * Called by the orchestrator at every rotation that selects
 * PIM_ANTI_PRIOR so the bias targets the picker's CURRENT
 * distribution rather than a snapshot frozen at the start of the
 * run.  Cheap: two O(MAX_NR_SYSCALL) walks on the rotation path
 * (one for the baseline sum, one for the per-syscall weight), never
 * on the hot pick path.  Visibility of the weight table is
 * published by the RELEASE-store of current_strategy that
 * maybe_rotate_strategy emits after select_next_strategy returns;
 * see the weight-array comment in struct shm_s.
 */
void plateau_anti_prior_refresh_baseline(void);

/*
 * Wall-lever shadow gate.  Returns true iff the candidate
 * syscall is a high-call zero-yield slot during a warm-plateau window
 * and a live wall-lever variant of the picker would suppress it to
 * reclaim its pick budget for productive / cold syscalls.  Eligibility
 * is precomputed per rotation by wall_lever_refresh_baseline(); the
 * hot path here reduces to a relaxed plateau_active probe plus a
 * single relaxed byte load from shm->wall_lever_suppress[nr].
 *
 * Returns false (do not suppress) when plateau_active is clear, when
 * the baseline has not yet been refreshed, when kcov_shm is
 * unavailable, or when nr is out of bounds, so the gate degrades
 * gracefully to today's byte-identical picker outside the wall-lever
 * operating window.  Safe to call from any picker path -- the function
 * is the entire shadow surface, callers only bump the would_suppress
 * stats counters on a true return.
 */
bool wall_lever_should_suppress_shadow(unsigned int nr);

/*
 * Recompute and publish the wall-lever baseline (mean of kcov_shm->
 * per_syscall_calls across the CURRENTLY ACTIVE syscalls -- biarch
 * sums the per-arch nr_active_* counts; uniarch reads nr_active_
 * syscalls -- so the dead-slot tail of the MAX_NR_SYSCALL array does
 * not deflate the threshold WALL_LEVER_HIGH_MULT scales against) and
 * the matching per-syscall suppression decision table
 * wall_lever_should_suppress_shadow consumes.  Called by the orchestrator at every rotation while
 * plateau_active is set, regardless of the chosen intervention mode,
 * so the shadow gate adapts to the fleet's CURRENT calls distribution
 * rather than freezing the eligibility set at a single moment.
 * Cheap: two O(MAX_NR_SYSCALL) walks on the rotation path (one for
 * the baseline sum, one for the per-syscall decision), never on the
 * hot pick path.  Visibility of the decision table is published by
 * the RELEASE-store of current_strategy that maybe_rotate_strategy
 * emits after select_next_strategy returns, mirroring the existing
 * plateau_anti_prior_refresh_baseline publish ordering.
 */
void wall_lever_refresh_baseline(void);

/*
 * Human-readable name for the intervention mode, for the dump path and
 * the rotation log.  Returns "?" for out-of-range input.
 */
const char *plateau_intervention_mode_name(enum plateau_intervention_mode m);

/*
 * Plateau hypothesis machinery.  On the rising-edge transition into
 * plateau_active the orchestrator captures a snapshot; a later
 * periodic tick diffs the current snapshot against entry and feeds
 * the per-counter delta into the rule evaluator, which publishes to
 * shm->plateau_current_hypothesis for per-call consumer gates.
 * See Documentation/strategy.md for the consumer contract, per-field
 * counter origins, and rule ordering.
 */
struct plateau_window_snapshot {
	unsigned long pc_edges;
	unsigned long cmp_unique;
	unsigned long bandit_edges;
	unsigned long explorer_edges;
	unsigned long childop_edges_total;
	unsigned long childop_calls_total;
	unsigned long remote_calls;
	unsigned long total_calls;
	unsigned long frontier_picks;
	unsigned long frontier_pulls;
	unsigned long frontier_live_picks;
	unsigned long frontier_silent_picks;
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
 * The saturating-subtract is load-bearing: a counter that wraps or
 * briefly inverts (concurrent readers / resets) produces 0 instead
 * of UINT_MAX, which would otherwise blow past every threshold in
 * the rule evaluator.
 */
void plateau_snapshot_delta(struct plateau_window_snapshot *out,
			    const struct plateau_window_snapshot *entry,
			    const struct plateau_window_snapshot *now);

/*
 * Plateau hypothesis classifier.  Each value names ONE hypothesis
 * about why discovery has stalled.  Invariant: rules are checked in
 * enum order and the FIRST match wins, so the ordering encodes
 * precedence -- CMP_RISING_PC_FLAT is most specific,
 * SINGLE_GROUP_DOMINANT is most general.  Thresholds live in
 * strategy_plateau_hypothesis_check() in strategy.c.
 * See Documentation/strategy.md for the design rationale.
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
 * bumps.  The per-tick driver (strategy_plateau_hypothesis_tick) wraps
 * the call with the publish-and-log bookkeeping; consumer gates in
 * child.c and minicorpus.c read the published value from shm rather
 * than re-running the rule check.
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
 * Called from main/loop.c print_stats() once per stats tick -- the
 * cadence matches the cadence the operator reads the periodic
 * dump at, so the hypothesis-transition log lines and the per-tick
 * visibility line stay in sync.
 */
void strategy_plateau_hypothesis_tick(void);

/*
 * Read-side accessors used by main/loop.c print_stats() to format the
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
void dump_strategy_stats(void) __cold;
