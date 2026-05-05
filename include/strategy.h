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
 * Per-strategy edge attribution is recorded in shm->edges_by_strategy[]
 * so the operator can A/B compare strategies across many windows; the
 * bandit picker derives its reward signal from the same counters via
 * the per-window edge delta computed at rotation time.
 *
 * Phase 1 ships two strategies (heuristic + uniform random); follow-up
 * commits add coverage-frontier, HEALER pair-bias, group-saturation,
 * newly-discovered, and genetic strategies (each becomes a new arm
 * the bandit picker can score against the existing ones).
 */

enum strategy_t {
	STRATEGY_HEURISTIC = 0,	/* default: group-bias + cold-skip + edgepair-bias */
	STRATEGY_RANDOM,	/* uniform pick, no biases */
	NR_STRATEGIES,
};

/* Fleet-wide rotation boundary, in ops.  ~100 sec at 10K iter/sec. */
#define STRATEGY_WINDOW (1UL << 20)	/* 1,048,576 ops */

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
 * Record the just-finished window's outcome for the bandit picker.
 * Bumps bandit_pulls[arm] and adds the per-window edge delta to
 * bandit_reward[arm].  Called from the CAS-winning child during
 * maybe_rotate_strategy(); a no-op when arm is out of range.
 */
void bandit_record_pull(int arm, unsigned long reward);

/*
 * Pick the arm to run during the next window.  In PICKER_ROUND_ROBIN
 * mode this is just (prev + 1) % NR_STRATEGIES; in PICKER_BANDIT_UCB1
 * mode this runs the UCB1 score across all arms (any unpulled arm
 * wins immediately during cold-start).
 */
int pick_next_strategy(int prev);

/*
 * End-of-run summary: per-arm pulls + cumulative reward + mean
 * edges/window.  Called from dump_stats().
 */
void dump_strategy_stats(void);
