/*
 * child-canary-stats.c -- Shared counter-read helpers for the dormant-
 * childop canary promotion queue.
 *
 * Owns the four helpers that abstract over shm / kcov_shm counter
 * reads used across multiple canary TUs:
 *   monotonic_seconds()      -- CLOCK_MONOTONIC wall-clock accessor
 *   window_iters_resolved()  -- effective window length with plateau
 *                               acceleration applied
 *   edges_for_op()           -- per-op clean-edge counter reader
 *   invocations_for_op()     -- per-op invocation counter reader
 *
 * All other canary state lives in child-canary-state.c,
 * child-canary-liveness.c, child-canary-picker.c, child-canary-policy.c,
 * child-canary-report.c, and child-canary-grace.c; all share
 * child-canary-internal.h.
 */
#include <stdbool.h>
#include <time.h>

#include "child-canary-internal.h"
#include "kcov.h"
#include "params.h"
#include "shm.h"

/* Lower / upper clamps on --canary-window; the parser enforces both,
 * but we keep the constants here so a code-side read of the bound is
 * always in agreement with the CLI. */
#define CANARY_WINDOW_ITERS_MIN		1000U
#define CANARY_WINDOW_ITERS_MAX		1000000U

/* Wall-clock-skew-immune second counter for state-transition stamps and
 * the summary throttle.  CLOCK_MONOTONIC cannot fail on a supported
 * kernel, so the return is taken unconditionally. */
time_t monotonic_seconds(void)
{
	struct timespec ts;
	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

unsigned int window_iters_resolved(void)
{
	unsigned int w = canary_window_iters;

	/* Plateau acceleration: when the fleet's KCOV new-edge rate has
	 * dropped below threshold the plateau flag is raised in shared
	 * memory.  Halve the effective canary window so each dormant op
	 * gets fewer iters to prove itself, the FIFO moves faster, and
	 * we sample more dormants per unit time.  The MIN/MAX clamp
	 * below still applies, so a halved value cannot fall below
	 * CANARY_WINDOW_ITERS_MIN. */
	if (kcov_shm != NULL &&
	    __atomic_load_n(&kcov_shm->plateau.plateau_active, __ATOMIC_ACQUIRE))
		w /= 2;

	if (w < CANARY_WINDOW_ITERS_MIN)
		w = CANARY_WINDOW_ITERS_MIN;
	if (w > CANARY_WINDOW_ITERS_MAX)
		w = CANARY_WINDOW_ITERS_MAX;
	return w;
}

/* Per-op edge counter consumed by the canary window's promote/demote
 * decision (CANARY_EDGE_THRESHOLD over a window of canary_window_iters
 * invocations).  Sourced from childop_edges_clean[], which is published
 * by the outer KCOV bracket in child_process() and reflects only the
 * edges attributable to this op's own dispatch -- no sibling traffic
 * mixed in.  Under --childop-kcov-attribution=off (default is dual) the
 * clean counter stays at zero and every window resolves to "zero_edges"
 * demote; that is the documented opt-out of the bracket path, matching
 * the no-KCOV degradation.  The noisier childop_edges_discovered[] is
 * still populated as a diagnostic comparator and surfaced in the stats
 * dump, but the scheduling decision now runs off the clean signal. */
unsigned long edges_for_op(enum child_op_type op)
{
	if (op >= NR_CHILD_OP_TYPES)
		return 0UL;
	return __atomic_load_n(&shm->stats.childop.edges_clean[op],
			       __ATOMIC_RELAXED);
}

/* Per-op invocation count, sourced from the shm-resident counter
 * bumped by every alt-op child in child_process()'s post-call block.
 * This is the canary window's clock: with one canary slot in a 16-
 * child fleet, the canary op's own invocation count grows roughly
 * 1/16 as fast as parent_stats.op_count, so sizing the window in
 * fleet-wide ops would close the window after only a fraction of the
 * intended sample.  Reading the per-op counter directly keeps the
 * CLI / log 'iters' label honest -- one iter == one canary-op call,
 * regardless of fleet size or canary-slot count. */
unsigned long invocations_for_op(enum child_op_type op)
{
	if (op >= NR_CHILD_OP_TYPES)
		return 0UL;
	return __atomic_load_n(&shm->stats.childop.invocations[op],
			       __ATOMIC_RELAXED);
}
