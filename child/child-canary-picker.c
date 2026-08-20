/*
 * child-canary-picker.c -- Candidate selection, tick loop, and
 * parked-slot recovery for the dormant-childop canary queue.
 *
 * Owns:
 *   - the two picker cursors (priority-seed and FIFO fallback),
 *   - the resolved priority-seed list pointer and its --canary-seed
 *     widened-storage backing,
 *   - the plateau-active edge-log latch,
 *   - pick_next_canary() (called by the state TU's init and by this
 *     TU's retry_parked_slot / stage_next_or_park tails),
 *   - retry_parked_slot / stage_next_or_park / close_window_or_park:
 *     picker-local tick helpers,
 *   - canary_queue_tick(), the ~1-s dispatcher that folds in the
 *     early-bail SETUP_BROKEN and wedge-stall demotes before delegating
 *     the full-window close to close_window_and_decide() in the state
 *     TU.
 *
 * State transitions themselves live in child-canary-state.c; this TU
 * only decides *when* to close a window, then calls the state TU's
 * exit hooks with the resolved outcome.
 */
#include <stdbool.h>
#include <time.h>

#include "child-api.h"
#include "child-canary-internal.h"
#include "kcov.h"
#include "params.h"
#include "shm.h"
#include "trinity.h"

/* Per-window setup-failure count above which a canary op with zero
 * setup successes is treated as structurally broken (vs. low-yield)
 * and the window is aborted early.  500 = enough to filter the slow
 * start of a transient EAGAIN/ENOMEM burst, well below the full
 * 10000-iter window so a re-test costs ~500 invocations not ~10000.
 * Tied to setup_ok_delta == 0: an op with any setup success at all
 * is not "broken at setup", just bad at it. */
#define CANARY_SETUP_BROKEN_FAILS	500U

/* Wall-clock ceiling on a canary window with zero invocations.  op_fn
 * bumps childop_invocations[op] only on return; if every dispatch of
 * the canaried op wedges inside a kernel syscall long enough to trip
 * the REAP_STALL_THRESHOLD_S s parent watchdog, the child is killed before that bump ever
 * lands and invocations stays at 0.  window_iters (measured off the
 * invocation delta) is then also 0, setup_fail_delta (invocations -
 * setup_accepted) is 0, and neither the SETUP_BROKEN branch nor the
 * iters >= budget branch below can fire -- the canary slot is pinned
 * on the hung op indefinitely and every other dormant op is starved
 * of a canary window.  600 s is ~20x the parent's REAP_STALL_THRESHOLD_S s per-child
 * stall detection so a genuinely slow op that eventually returns is
 * not misclassified as wedged. */
#define CANARY_WEDGE_STALL_SEC	600U

/* Picker cursors.  canary_priority_cursor is the next index into
 * canary_priority_list (the per-run random shuffle, or the operator-
 * supplied override).  fifo_cursor is the last enum value picked from
 * the general FIFO walk; the next pick resumes from cursor+1 and wraps. */
unsigned int canary_priority_cursor = 0;
enum child_op_type canary_fifo_cursor = CHILD_OP_SYSCALL;

/* Resolved priority list pointer.  Defaults to a per-epoch random shuffle
 * of every eligible op (built in canary_queue_init()); if --canary-seed
 * was passed, the parser put op enums into canary_seed_override[] /
 * canary_seed_override_count and the init path swaps that in. */
const enum child_op_type *canary_priority_list = NULL;
unsigned int canary_priority_list_count = 0;

/* Storage backing canary_priority_list when --canary-seed is in use.  The
 * parser stuffs unsigned-char-narrowed op enums into
 * canary_seed_override[]; we widen them into a real enum array here so
 * the picker can iterate by value rather than by re-casting on every
 * pick. */
enum child_op_type canary_seed_override_widened[CANARY_SEED_OVERRIDE_MAX];

/* Last observed plateau_active value, used for edge-triggered logging in
 * canary_queue_tick().  File-static (not a function-local static) so
 * canary_queue_init() can reset it per-epoch -- otherwise stale state from
 * the previous epoch would suppress the first plateau-change log of the
 * new epoch (or emit a spurious one if the flag flipped while the queue
 * was reinitialising). */
bool canary_last_plateau = false;

/* --------------------------------------------------------------------
 * Picker.
 * -------------------------------------------------------------------- */

bool pick_next_canary(enum child_op_type *out)
{
	unsigned int safety;
	enum child_op_type op;
	time_t now;

	/* Priority pass: the randomised first-pass order (or operator
	 * override).  fork-pressure drain is consulted here so a pid-heavy
	 * op defers to the next entry during the recovery window instead
	 * of being skipped permanently:
	 * the cursor is NOT advanced past a suppressed entry, so the
	 * picker walks back to it once the window expires and a later
	 * tick re-enters via retry_parked_slot(). */
	while (canary_priority_cursor < canary_priority_list_count) {
		op = canary_priority_list[canary_priority_cursor];
		if (op == CHILD_OP_SYSCALL || op >= NR_CHILD_OP_TYPES) {
			canary_priority_cursor++;
			continue;
		}
		if (canary_ops[op].state == CANARY_STATE_CONFIG_BLOCKED) {
			canary_priority_cursor++;
			continue;
		}
		if (canary_ops[op].phase1_ineligible) {
			canary_priority_cursor++;
			continue;
		}
		if (canary_ops[op].state == CANARY_STATE_PROMOTED) {
			canary_priority_cursor++;
			continue;
		}
		if (fork_pressure_should_suppress(op))
			break;
		canary_priority_cursor++;
		*out = op;
		return true;
	}

	/* FIFO fallback: walk the general dormant pool.  Walks
	 * the enum in numerical order from fifo_cursor+1, wrapping.
	 * Skips CONFIG_BLOCKED, risky-defer, priority seeds (already consumed
	 * or skipped above), PROMOTED, and DEMOTED entries still inside
	 * their backoff window.  A DEMOTED whose backoff has elapsed
	 * transitions back to DORMANT here and is then eligible. */
	now = monotonic_seconds();
	for (safety = 0; safety < NR_CHILD_OP_TYPES; safety++) {
		canary_fifo_cursor =
			(enum child_op_type)((canary_fifo_cursor + 1) %
					     NR_CHILD_OP_TYPES);
		op = canary_fifo_cursor;
		if (op == CHILD_OP_SYSCALL)
			continue;
		if (canary_ops[op].state == CANARY_STATE_CONFIG_BLOCKED)
			continue;
		if (canary_ops[op].phase1_ineligible)
			continue;
		if (canary_ops[op].state == CANARY_STATE_PROMOTED)
			continue;
		if (canary_ops[op].state == CANARY_STATE_CANARYING)
			continue;
		if (canary_ops[op].state == CANARY_STATE_DEMOTED) {
			/* A setup-broken op carries a longer backoff than a
			 * routine zero-edges demotion: its failure shape
			 * needs a code fix, not a wait.  The flag is
			 * cleared in enter_canarying() so a recovered op
			 * falls back to the normal cadence on its next
			 * demote (if any). */
			time_t backoff = canary_op_setup_broken[op]
				? (time_t)CANARY_SETUP_BROKEN_BACKOFF_TIME
				: (time_t)CANARY_BACKOFF_TIME;
			if (now - canary_ops[op].last_state_transition <
			    backoff)
				continue;
			/* Backoff elapsed -- promote back to DORMANT
			 * and re-enter the picker pool.  Log the
			 * transition for operator visibility. */
			canary_ops[op].state = CANARY_STATE_DORMANT;
			canary_ops[op].last_state_transition = now;
			output(0, "canary: %s backoff complete, re-queued for canary\n",
				canary_ops[op].name);
		}
		/* Skip priority seeds in the FIFO walk only if it's already been
		 * canaried at least once (queue handled it already); a
		 * priority seed that demoted-then-recovered should be
		 * eligible again via the same backoff path as any other
		 * op. */
		if (canary_ops[op].state == CANARY_STATE_DORMANT) {
			/* fork-pressure drain: skip pid-heavy ops while
			 * the recovery window is active.  The FIFO cursor
			 * has already been advanced for this iteration,
			 * so a suppressed op falls through to the next
			 * candidate; once the window expires a later tick
			 * re-enters the picker and wraps back around to
			 * pick it up. */
			if (fork_pressure_should_suppress(op))
				continue;
			*out = op;
			return true;
		}
	}
	return false;
}

/* Parked-slot retry.  When the previous tick exhausted the picker we
 * cleared canary_active_op_set and raised canary_slots_parked.  The
 * canary_active_op_set early-return in canary_queue_tick() would
 * otherwise mean every subsequent tick bails before pick_next_canary()
 * runs again, so the dormant-op promotion path would silently die the
 * moment the first parking happened.  Re-run the picker here; if a
 * DEMOTED op's backoff has elapsed (or any other newly-eligible
 * candidate has appeared) enter_canarying() stages it and clears the
 * parked flag.  canary_active_op_set stays false until the killed slot
 * child is re-forked and canary_queue_on_child_respawn() commits the
 * staged op, so the dispatcher still falls through its early-return
 * on this tick.
 *
 * Returns true when the dispatcher should bail this tick (parked and
 * the picker is still empty); false when nothing needs to happen or
 * a new op has been staged. */
static bool retry_parked_slot(void)
{
	enum child_op_type next;

	if (!canary_slots_parked)
		return false;
	if (pick_next_canary(&next)) {
		enter_canarying(next);
		return false;
	}
	return true;
}

/* End-of-window decision.  iters has reached the resolved budget, so
 * close the current op's window (which records the
 * promote/demote/finish verdict on canary_ops[op]) and try to stage
 * the next candidate from the picker.  If the picker is exhausted
 * the slot is parked instead: the just-closed window's child is
 * still alive with the demoted/finished op stamped at fork time, and
 * dedicated alt-op children keep child->op_type for life, so without
 * intervention that slot would keep running the just-demoted op
 * throughout the entire backoff window AND crashes from it would be
 * silently dropped because canary_active_op_set is false.  Parking
 * clears active/pending state and recycles the slot child via the
 * same kill path the window-transition uses; when spawn_child()
 * respawns it, canary_slot_active() still returns true (parked, not
 * disabled) so the canary branch of assign_dedicated_alt_op() runs,
 * but canary_active_op() returns CHILD_OP_SYSCALL while parked,
 * which drops the slot back into the default syscall picker -- no
 * demoted alt-op runs in the meantime.  The next tick re-enters the
 * picker via retry_parked_slot() at the top of canary_queue_tick();
 * if pick_next_canary() still fails the slot stays parked until
 * then. */
/* Tail shared between the full-window close path and the early-bail
 * path: pick the next eligible canary candidate, or park the slot(s)
 * if the picker is exhausted.  Mirrors the parking rationale on
 * close_window_or_park() above -- without parking, a just-demoted op
 * keeps running on the slot until its dedicated child respawns
 * naturally (which on a parked queue is "never"), and crashes from
 * it get dropped because canary_active_op_set is false. */
static void stage_next_or_park(void)
{
	enum child_op_type next;

	if (pick_next_canary(&next)) {
		enter_canarying(next);
		return;
	}
	canary_pending_op_set = false;
	canary_active_op_set = false;
	canary_active_op_cell = CHILD_OP_SYSCALL;
	canary_pending_op = CHILD_OP_SYSCALL;
	canary_slots_parked = true;
	output(0, "canary queue: picker exhausted, parking slot(s) until next eligible op\n");
	kill_canary_slot_children();
}

static void close_window_or_park(enum child_op_type op)
{
	close_window_and_decide(op);
	/* PC-trial retry path: close_window_and_decide() may have re-
	 * canaried the SAME op via enter_canarying() when the just-closed
	 * window logged bracket attempts but zero opens (every slot child
	 * was KCOV_MODE_CMP).  In that case the op is back in
	 * CANARY_STATE_CANARYING and enter_canarying() has already staged
	 * it as pending + killed the slot children -- calling
	 * stage_next_or_park() here would pick a DIFFERENT op and clobber
	 * the staged retry, silently defeating the retry gate. */
	if (canary_ops[op].state == CANARY_STATE_CANARYING)
		return;
	stage_next_or_park();
}

/* Edge-triggered visibility for the plateau-driven window shrink.
 * Log on both rising and falling edges so the operator can see the
 * effective budget change in real time. */
static void log_plateau_edge(void)
{
	bool now_plateau = (kcov_shm != NULL &&
		__atomic_load_n(&kcov_shm->plateau.plateau_active,
				__ATOMIC_ACQUIRE));
	if (now_plateau == canary_last_plateau)
		return;
	output(0, "canary queue: plateau %s; effective window now %u iters\n",
		now_plateau
			? "entered, halving canary window"
			: "lifted, restoring canary window",
		window_iters_resolved());
	canary_last_plateau = now_plateau;
}

void canary_queue_tick(void)
{
	enum child_op_type op;
	unsigned long iters;
	unsigned long now_invocations;
	unsigned long now_edges;
	unsigned int budget;

	if (!canary_queue_live)
		return;

	log_plateau_edge();

	if (retry_parked_slot())
		return;

	if (!canary_active_op_set)
		return;

	op = canary_active_op_cell;
	if (op >= NR_CHILD_OP_TYPES)
		return;
	if (canary_ops[op].state != CANARY_STATE_CANARYING)
		return;

	now_invocations = invocations_for_op(op);
	now_edges = edges_for_op(op);
	iters = (now_invocations >= canary_ops[op].window_start_invocations)
		? (now_invocations - canary_ops[op].window_start_invocations) : 0;
	budget = window_iters_resolved();

	/* Per-window progress line.  Emitted at -v on every tick while
	 * CANARYING; the noise floor is bounded by the 1-s tick cadence
	 * times canary_slots (with 1 slot -> ~1 line/sec). */
	{
		unsigned long edges = (now_edges >= canary_ops[op].window_start_edges)
			? (now_edges - canary_ops[op].window_start_edges) : 0;
		output(1, "canary: %s in window %lu/%u iters (edges=%lu crashes=%u)\n",
			canary_ops[op].name, iters, budget,
			edges, canary_ops[op].window_crashes);
	}

	/* EARLY-BAIL on a structurally broken setup path.  An op whose
	 * setup_ok stays at zero while setup_failures climbs past
	 * CANARY_SETUP_BROKEN_FAILS is broken at the dispatch boundary
	 * (missing kconfig, capability, netns) -- it will not produce
	 * any edges no matter how long the window runs, so close the
	 * window now with the SETUP_BROKEN demote reason and recycle
	 * the slot.  Distinct from the zero_edges close below: that
	 * one means the op RAN but produced nothing; this one means
	 * the op never ran successfully at all.
	 *
	 * The deltas are read from the same shm counters
	 * close_window_and_decide()'s shadow path uses, so the two
	 * sites stay consistent on the broken-vs-barren distinction. */
	{
		unsigned long now_setup_accepted = __atomic_load_n(
			&shm->stats.childop.setup_accepted[op], __ATOMIC_RELAXED);
		unsigned long setup_ok_delta =
			(now_setup_accepted > canary_ops[op].window_start_setup_accepted)
			? (now_setup_accepted - canary_ops[op].window_start_setup_accepted) : 0;
		unsigned long now_setup_failures =
			(now_invocations > now_setup_accepted)
			? (now_invocations - now_setup_accepted) : 0;
		unsigned long setup_fail_delta =
			(now_setup_failures > canary_ops[op].window_start_setup_failures)
			? (now_setup_failures - canary_ops[op].window_start_setup_failures) : 0;

		if (setup_ok_delta == 0 &&
		    setup_fail_delta >= (unsigned long)CANARY_SETUP_BROKEN_FAILS) {
			leave_canarying_demote_setup_broken(op, iters, setup_fail_delta);
			stage_next_or_park();
			return;
		}
	}

	/* Wedge-stall bail-out.  invocations bumps at op_fn's return, so
	 * a childop whose every call wedges long enough for the parent
	 * watchdog to kill it before op_fn returns leaves iters at 0
	 * indefinitely -- the SETUP_BROKEN branch above cannot fire
	 * (setup_fail_delta is also 0), and the iters >= budget branch
	 * below never reaches the threshold.  Bound the window on wall
	 * time instead so the canary slot is not pinned on the hung op
	 * forever and every subsequent dormant op gets its window. */
	if (iters == 0) {
		time_t now = monotonic_seconds();
		time_t window_age = (now >= canary_ops[op].last_canary_window_start)
			? (now - canary_ops[op].last_canary_window_start) : 0;
		if (window_age >= (time_t)CANARY_WEDGE_STALL_SEC) {
			leave_canarying_demote_wedged(op, window_age);
			stage_next_or_park();
			return;
		}
	}

	if (iters >= (unsigned long)budget)
		close_window_or_park(op);
}
