#pragma once

/*
 * Multi-strategy syscall-selection rotation.
 *
 * Each strategy implements a distinct pick_syscall policy.  Different
 * strategies have different blind spots; rotating through them surfaces
 * bug classes that any single policy systematically suppresses.
 *
 * The active strategy is fleet-wide (single shm-resident enum, every
 * child reads it on each syscall pick) and rotates round-robin every
 * STRATEGY_WINDOW ops.  Window size is sized for ~100 sec at 10K
 * iter/sec — long enough for each strategy to build kernel state,
 * short enough to amortise the strategy switch cost.
 *
 * Per-strategy edge attribution is recorded in shm->edges_by_strategy[]
 * so the operator can A/B compare strategies across many windows.
 *
 * Phase 1 ships two strategies (heuristic + uniform random); follow-up
 * commits add bandit, coverage-frontier, HEALER pair-bias, group-
 * saturation, newly-discovered, and genetic strategies.
 */

enum strategy_t {
	STRATEGY_HEURISTIC = 0,	/* default: group-bias + cold-skip + edgepair-bias */
	STRATEGY_RANDOM,	/* uniform pick, no biases */
	NR_STRATEGIES,
};

/* Fleet-wide rotation boundary, in ops.  ~100 sec at 10K iter/sec. */
#define STRATEGY_WINDOW (1UL << 20)	/* 1,048,576 ops */
