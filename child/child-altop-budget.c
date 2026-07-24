/*
 * Adaptive per-op budget multiplier and the decaying-recency edge/wall
 * ring for the childop invocations.  Split out of child-altop.c so the
 * budget-feedback and window-rotate paths compile independently of the
 * static tables the picker consumes.
 *
 * adapt_budget() is invoked from the per-iteration hot path in
 * child.c whenever the outer KCOV bracket fires; the decay-ring
 * producers are invoked from the same iteration under the is_alt_op
 * gate; childop_window_advance() is driven from the 600 s periodic
 * dump tick.  All producer atomics stay RELAXED as before.
 */


#include <string.h>
#include "child.h"
#include "child-internal.h"
#include "params.h"
#include "rnd.h"
#include "shm.h"
#include "stats.h"
#include "strategy.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/socket.h"
#include "kernel/mount.h"
#include "kernel/if_packet.h"

/*
 * Post-invocation feedback for the per-childop budget multiplier.
 *
 * The caller hands us the per-call edge delta surfaced by the outer
 * KCOV bracket (kcov_bracket_end's return value for this dispatch),
 * i.e. the clean count of edges attributable to THIS op's invocation
 * with no sibling-traffic noise mixed in.  If the delta clears
 * ADAPT_BUDGET_THRESHOLD we treat the invocation as productive: bump
 * the multiplier by 25% (Q8.8 *5/4) and clear the zero-streak.
 * Otherwise increment the zero-streak; once it hits
 * ADAPT_BUDGET_ZERO_STREAK the shrink ratchet fires (multiplier *4/5)
 * and the streak resets.  Both moves clamp to [ADAPT_BUDGET_MIN,
 * ADAPT_BUDGET_MAX].
 *
 * Caveats deliberately accepted:
 *
 *   - The caller only invokes adapt_budget when the outer bracket
 *     fired (mode != OFF, op_uses_outer_bracket(op), and
 *     kcov_bracket_begin succeeded).  Calls that did not bracket
 *     leave the multiplier untouched -- a quiet "no signal this
 *     iteration" rather than a ratchet driven by sibling noise.
 *     Ops permanently excluded from the bracket (CHILD_OP_SYSCALL,
 *     CHILD_OP_SCHED_CYCLER -- see op_uses_outer_bracket) therefore
 *     stay at the unity multiplier, matching the no-KCOV degradation
 *     path.  CHILD_OP_SYSCALL has its own cold-syscall heuristics
 *     inside kcov.c that this loop must not fight for control of the
 *     dominant ~95% path; the bracket exclusion already enforces that.
 *
 *   - Updates are RELAXED non-RMW stores.  Two children tail-racing on
 *     the same op_type can lose an update; the worst case is the
 *     ratchet converges a few invocations later than the strict-RMW
 *     model would.  Ratchet caps make divergence bounded in either
 *     direction.
 */
void adapt_budget(enum child_op_type op_type,
			 unsigned long edges_this_call)
{
	uint16_t mult, new_mult;
	uint16_t streak;
	unsigned long delta;

	if (op_type == CHILD_OP_SYSCALL || op_type >= NR_CHILD_OP_TYPES)
		return;

	mult = __atomic_load_n(&shm->stats.childop.budget_mult[op_type],
			       __ATOMIC_RELAXED);
	if (mult == 0)
		mult = ADAPT_BUDGET_UNITY;

	delta = edges_this_call;

	if (delta >= ADAPT_BUDGET_THRESHOLD) {
		/* Productive: boost by 25% (Q8.8 *5/4), clamped at the cap. */
		new_mult = (uint16_t)((unsigned int)mult * 5U / 4U);
		if (new_mult > ADAPT_BUDGET_MAX)
			new_mult = ADAPT_BUDGET_MAX;
		__atomic_store_n(&shm->stats.childop.zero_streak[op_type],
				 0, __ATOMIC_RELAXED);
	} else {
		/* Hysteresis: only shrink after ADAPT_BUDGET_ZERO_STREAK
		 * consecutive sub-threshold invocations, so a single noise
		 * dip doesn't immediately cut the budget. */
		streak = (uint16_t)__atomic_add_fetch(
			&shm->stats.childop.zero_streak[op_type],
			1, __ATOMIC_RELAXED);
		if (streak < ADAPT_BUDGET_ZERO_STREAK)
			return;
		new_mult = (uint16_t)((unsigned int)mult * 4U / 5U);
		if (new_mult < ADAPT_BUDGET_MIN)
			new_mult = ADAPT_BUDGET_MIN;
		__atomic_store_n(&shm->stats.childop.zero_streak[op_type],
				 0, __ATOMIC_RELAXED);
	}

	if (new_mult != mult)
		__atomic_store_n(&shm->stats.childop.budget_mult[op_type],
				 new_mult, __ATOMIC_RELAXED);
}

_Static_assert((CHILDOP_DECAY_WINDOWS &
		(CHILDOP_DECAY_WINDOWS - 1)) == 0,
	       "CHILDOP_DECAY_WINDOWS must be a power of two");

/*
 * Per-childop decaying-ring producer: bump the active slot's edge count
 * by `edges` and bump the cached running sum in lockstep.  See the
 * include/stats.h comment on childop_edge_history[][] for the shape
 * contract; the prototype block in include/child.h covers the multi-
 * producer race envelope.  No-op on out-of-range op (defensive: the
 * producer site in child.c already filters CHILD_OP_SYSCALL via the
 * is_alt_op gate, but the test costs nothing and keeps the helper safe
 * to drop into other call sites) and on a zero delta (a clean-edge
 * dispatch that returned no fresh edges should not perturb the cached
 * sum or burn an atomic).
 */
void childop_decay_record_edges(enum child_op_type op, unsigned long edges)
{
	unsigned int slot;

	if (op >= NR_CHILD_OP_TYPES || edges == 0)
		return;

	slot = __atomic_load_n(&shm->stats.childop.decay_slot,
			       __ATOMIC_RELAXED) &
	       (CHILDOP_DECAY_WINDOWS - 1);
	__atomic_fetch_add(&shm->stats.childop.edge_history[op][slot],
			   edges, __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->stats.childop.edge_recent_cached[op],
			   edges, __ATOMIC_RELAXED);
}

/*
 * Sister of childop_decay_record_edges(): bump the active slot's wall-
 * time accumulator (nanoseconds) and the matching cached running sum.
 * The producer site in child.c already clamps `ns` to >= 0 (see the
 * CLOCK_MONOTONIC subtraction at child.c:796-799), so a backward clock
 * step cannot drive the cached sum negative here; the >= 0 clamp lives
 * in the producer, not in this helper, matching the existing childop_
 * wall_ns[] add-fetch pattern at child.c:803-804.
 */
void childop_decay_record_wall(enum child_op_type op, unsigned long ns)
{
	unsigned int slot;

	if (op >= NR_CHILD_OP_TYPES || ns == 0)
		return;

	slot = __atomic_load_n(&shm->stats.childop.decay_slot,
			       __ATOMIC_RELAXED) &
	       (CHILDOP_DECAY_WINDOWS - 1);
	__atomic_fetch_add(&shm->stats.childop.wall_history[op][slot],
			   ns, __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->stats.childop.wall_recent_cached[op],
			   ns, __ATOMIC_RELAXED);
}

/*
 * Window-advance rotator for the per-childop decaying recency ring.
 * Clear-then-publish, mirroring frontier_window_advance()'s ordering
 * fix: compute the next slot index without publishing it, exchange the
 * next slot to zero on every per-op edge AND wall history row while
 * producers are still targeting the previous slot, subtract the just-
 * cleared slot's contribution from the cached running sums under a CAS
 * loop (saturating-subtract guard against a racing producer fetch-add
 * that lands between our exchange and our subtract), and only then bump
 * childop_decay_slot.  A producer racing the rotation keeps adding into
 * the previous slot for a handful of instructions -- a bounded window-
 * boundary attribution error -- instead of having its addition silently
 * dropped or inverting the cached sum.
 *
 * SHADOW: nothing in the picker / canary path reads the ring; the only
 * reader is dump_stats_childop_decay_recency() at shutdown, so the
 * rotation cadence only affects which window appears as "recent" in the
 * dump.  Driven from childop_periodic_dump_and_advance()
 * (stats/periodic/childop-split.c) at the same 600 s tick as the other
 * operator-visibility dumps so the recency horizon is on the order of
 * one dump interval x CHILDOP_DECAY_WINDOWS.
 */
void childop_window_advance(void)
{
	unsigned int cur, next;
	enum child_op_type op;

	cur = __atomic_load_n(&shm->stats.childop.decay_slot,
			      __ATOMIC_RELAXED);
	next = (cur + 1U) & (CHILDOP_DECAY_WINDOWS - 1);

	for (op = CHILD_OP_SYSCALL + 1; op < NR_CHILD_OP_TYPES; op++) {
		unsigned long old_edge_slot, old_wall_slot;
		unsigned long old_cached;

		old_edge_slot = __atomic_exchange_n(
				&shm->stats.childop.edge_history[op][next],
				0UL, __ATOMIC_RELAXED);
		old_wall_slot = __atomic_exchange_n(
				&shm->stats.childop.wall_history[op][next],
				0UL, __ATOMIC_RELAXED);

		/* Edge cached: CAS-clamped subtract.  Producers should not be
		 * racing this op at this point (childop_decay_slot still names
		 * the previous slot) but the loop costs at most a handful of
		 * retries and removes the underflow case unconditionally; the
		 * saturating-subtract guard is required even with the reorder
		 * because a producer that landed in the freshly-cleared slot
		 * before our exchange landed its cached add too. */
		old_cached = __atomic_load_n(
				&shm->stats.childop.edge_recent_cached[op],
				__ATOMIC_RELAXED);
		for (;;) {
			unsigned long new_sum;

			new_sum = (old_cached >= old_edge_slot)
				? (old_cached - old_edge_slot) : 0UL;
			if (__atomic_compare_exchange_n(
				    &shm->stats.childop.edge_recent_cached[op],
				    &old_cached, new_sum, false,
				    __ATOMIC_RELAXED, __ATOMIC_RELAXED))
				break;
		}

		old_cached = __atomic_load_n(
				&shm->stats.childop.wall_recent_cached[op],
				__ATOMIC_RELAXED);
		for (;;) {
			unsigned long new_sum;

			new_sum = (old_cached >= old_wall_slot)
				? (old_cached - old_wall_slot) : 0UL;
			if (__atomic_compare_exchange_n(
				    &shm->stats.childop.wall_recent_cached[op],
				    &old_cached, new_sum, false,
				    __ATOMIC_RELAXED, __ATOMIC_RELAXED))
				break;
		}
	}

	/* Publish the new slot only after every per-op clear has landed.
	 * From this point producers see the freshly-zeroed slot. */
	__atomic_store_n(&shm->stats.childop.decay_slot, cur + 1U,
			 __ATOMIC_RELAXED);
}
