/*
 * child-canary-report.c -- Reporting, per-tick summaries, and public
 * queries into the dormant-childop canary queue's active op.
 *
 * Owns:
 *   - the recently-promoted ring rendered by the 60-s summary line,
 *   - the summary's own throttle timestamp,
 *   - the crash-and-respawn observation surface (canary_queue_on_crash),
 *   - the read-only public queries (canary_slot_active, canary_active_op,
 *     canary_op_is_promoted) that live-time consumers (spawn_child,
 *     assign_dedicated_alt_op) call on every fork.
 *
 * State transitions (enter / leave / commit-respawn) live in
 * child-canary-state.c; this TU only observes.
 */
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#include "child-api.h"
#include "child-canary-internal.h"
#include "child.h"
#include "params.h"
#include "shm.h"
#include "trinity.h"

/* Queue-summary cadence (60 s; spec verbatim).  Per-window-progress
 * lines are emitted from the ~1 s tick path with no extra rate-limit
 * (one line per tick while CANARYING). */
#define CANARY_SUMMARY_INTERVAL_SEC	60

/* Recently-promoted op names, ring of last CANARY_PROMOTION_RING_SIZE
 * entries.  Rendered by the 60-s summary line when at least one
 * promotion has occurred. */
enum child_op_type canary_promotion_ring[CANARY_PROMOTION_RING_SIZE];
unsigned int canary_promotion_ring_count = 0;
unsigned int canary_promotion_ring_head = 0;

/* Cached time of last summary emit; the summary self-rate-limits. */
time_t canary_last_summary = 0;

void push_promotion(enum child_op_type op)
{
	canary_promotion_ring[canary_promotion_ring_head] = op;
	canary_promotion_ring_head =
		(canary_promotion_ring_head + 1) % CANARY_PROMOTION_RING_SIZE;
	if (canary_promotion_ring_count < CANARY_PROMOTION_RING_SIZE)
		canary_promotion_ring_count++;
}

void canary_queue_summary(void)
{
	unsigned int dormant = 0, canarying = 0, promoted = 0;
	unsigned int demoted = 0, blocked = 0;
	unsigned int blocked_config = 0, blocked_broken = 0, blocked_nobracket = 0;
	unsigned int total = 0;
	unsigned int i;
	time_t now;

	if (!canary_queue_live)
		return;

	now = monotonic_seconds();
	if (now - canary_last_summary < CANARY_SUMMARY_INTERVAL_SEC)
		return;
	canary_last_summary = now;

	for (i = (unsigned int)CHILD_OP_SYSCALL + 1; i < NR_CHILD_OP_TYPES; i++) {
		total++;
		switch (canary_ops[i].state) {
		case CANARY_STATE_DORMANT:		dormant++; break;
		case CANARY_STATE_CANARYING:		canarying++; break;
		case CANARY_STATE_PROMOTED:		promoted++; break;
		case CANARY_STATE_DEMOTED:		demoted++; break;
		case CANARY_STATE_CONFIG_BLOCKED:
			blocked++;
			switch (canary_ops[i].blocked_reason) {
			case CANARY_BLOCKED_REASON_CONFIG_ABSENT:
				blocked_config++; break;
			case CANARY_BLOCKED_REASON_SETUP_BROKEN:
				blocked_broken++; break;
			case CANARY_BLOCKED_REASON_NO_OUTER_BRACKET:
				blocked_nobracket++; break;
			case CANARY_BLOCKED_REASON_NONE:
				/* Should never happen -- every CONFIG_BLOCKED
				 * assignment sets a reason.  Fall through so an
				 * unset field still counts in the total blocked
				 * tally, just not in any subreason bucket. */
				break;
			}
			break;
		}
	}

	output(0, "canary queue: %u dormant, %u canarying, %u promoted, %u demoted, %u config-blocked [config-absent=%u setup-broken=%u no-outer-bracket=%u] (total=%u)\n",
		dormant, canarying, promoted, demoted, blocked,
		blocked_config, blocked_broken, blocked_nobracket, total);

	/* When the fleet has any non-dedicated random children (i.e.
	 * max_children > alt_op_children), those children's snapshots
	 * of the dormant gate are fork-time COW copies and do not pick
	 * up promotion/demotion until they respawn.  Flag it in the
	 * periodic summary so the operator can read the queue state
	 * without assuming instant propagation. */
	if (max_children > alt_op_children)
		output(0, "canary queue: state propagates on respawn (non-dedicated random children carry fork-time gate snapshots)\n");

	if (canary_promotion_ring_count > 0) {
		char buf[512];
		size_t off = 0;
		unsigned int j, start;

		start = (canary_promotion_ring_head +
			 CANARY_PROMOTION_RING_SIZE -
			 canary_promotion_ring_count) %
			CANARY_PROMOTION_RING_SIZE;
		for (j = 0; j < canary_promotion_ring_count; j++) {
			enum child_op_type op =
				canary_promotion_ring[(start + j) %
						      CANARY_PROMOTION_RING_SIZE];
			int n = snprintf(buf + off, sizeof(buf) - off,
				"%s%s", off ? ", " : "", alt_op_name(op));
			if (n <= 0 || (size_t)n >= sizeof(buf) - off)
				break;
			off += (size_t)n;
		}
		output(0, "canary queue: last %u promotions: %s\n",
			canary_promotion_ring_count, buf);
	}
}

void canary_queue_on_crash(int childno, int signo)
{
	enum child_op_type op;

	if (!canary_queue_live)
		return;
	if (canary_slots == 0 || childno < 0)
		return;
	if ((unsigned int)childno >= canary_slots)
		return;
	if (signo != SIGSEGV && signo != SIGBUS &&
	    signo != SIGILL && signo != SIGABRT)
		return;

	/* The op identity is read from the dying child's slot.  In a
	 * canary slot, child->op_type is the op the parent stamped in
	 * assign_dedicated_alt_op() at fork time.  Children are not
	 * supposed to mutate it for canary slots (use_dedicated_op is
	 * true there and pick_op_type() is skipped).  Defensive: skip
	 * crashes where the op is not the active canary op (e.g. the
	 * crash landed on the pre-transition op before the kill_pid
	 * respawn took). */
	if (!canary_active_op_set)
		return;
	op = canary_active_op_cell;
	if (op >= NR_CHILD_OP_TYPES)
		return;
	if (canary_ops[op].state != CANARY_STATE_CANARYING)
		return;
	if (children == NULL || children[childno] == NULL)
		return;
	if (children[childno]->op_type != op)
		return;

	canary_ops[op].window_crashes++;
}

bool canary_slot_active(int childno)
{
	if (!canary_queue_live)
		return false;
	if (canary_slots == 0 || childno < 0)
		return false;
	if ((unsigned int)childno >= canary_slots)
		return false;
	/* Before the first canary respawn lands we have no committed
	 * op yet -- stamp the pending op so the first fork picks up
	 * the queue's first pick rather than starting on a stale
	 * alt_op_rotation[] entry.  After that, the active cell is
	 * the source of truth.  When parked (picker exhausted), still
	 * claim the slot so the canary branch of assign_dedicated_alt_op
	 * runs and canary_active_op() returns CHILD_OP_SYSCALL --
	 * otherwise the slot would fall back to alt_op_rotation[] and
	 * pick up an arbitrary alt-op instead of the inert default. */
	return canary_active_op_set || canary_pending_op_set ||
	       canary_slots_parked;
}

enum child_op_type canary_active_op(void)
{
	if (canary_active_op_set)
		return canary_active_op_cell;
	if (canary_pending_op_set)
		return canary_pending_op;
	/* Parked: stamp the slot with the default syscall op so the
	 * child runs the normal pick_op_type() path until the queue
	 * stages a new pending op. */
	return CHILD_OP_SYSCALL;
}

bool canary_op_is_promoted(enum child_op_type op)
{
	if (!canary_queue_live)
		return false;
	if ((unsigned int)op >= NR_CHILD_OP_TYPES)
		return false;
	return canary_ops[op].state == CANARY_STATE_PROMOTED;
}
