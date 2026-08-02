/*
 * child-canary-state.c -- State transitions + init for the dormant-
 * childop canary promotion queue.
 *
 * Design write-up: see Documentation/childop-canary-queue.md
 *
 * Invariant: state lives entirely in parent-private static memory;
 * runtime flips are parent-only, not shm-resident.
 *
 * This TU owns:
 *   - the parent-private state cells (canary_ops[], the two-stage
 *     active/pending op cells, the parked/live flags, the setup-broken
 *     latch),
 *   - the shared helpers (monotonic_seconds, window_iters_resolved,
 *     edges_for_op, invocations_for_op, op_kcov_skip_reason),
 *   - the state-transition entry/exit hooks (enter_canarying,
 *     leave_canarying_promote/demote/setup_broken/wedged/ineligible,
 *     canary_health_verdict, close_window_and_decide),
 *   - the shadow recommended-state helpers,
 *   - the two-stage-commit respawn hook (canary_queue_on_child_respawn),
 *   - canary_queue_init.
 *
 * The picker + tick loop, the summary/report/query surface, and the
 * static policy tables live in child-canary-picker.c,
 * child-canary-report.c, and child-canary-policy.c respectively; all
 * four TUs share child-canary-internal.h.
 */
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "child-canary-internal.h"
#include "kcov.h"
#include "params.h"
#include "pids.h"
#include "shm.h"
#include "stats_ring.h"
#include "trinity.h"
#include "utils.h"

/* --------------------------------------------------------------------
 * Concrete thresholds.  Kept as #defines rather than CLI flags so the
 * operator-facing surface stays small.
 * The two operator-tunable knobs (slot count, window iters) come in
 * through --canary-slots / --canary-window in main/params/.
 * -------------------------------------------------------------------- */

/* Lower / upper clamps on --canary-window; the parser enforces both,
 * but we keep the constants here so a code-side read of the bound is
 * always in agreement with the CLI. */
#define CANARY_WINDOW_ITERS_MIN		1000U
#define CANARY_WINDOW_ITERS_MAX		1000000U

/* New edges per window required to call a canary "productive".  Tight
 * enough to filter sibling-mediated KCOV noise and loose enough to
 * admit any op that actually exercises a non-trivial code path. */
#define CANARY_EDGE_THRESHOLD		50UL

/* SIGSEGV/SIGBUS/SIGILL/SIGABRT per window before we treat the op as
 * the cause of the crash and demote it.  1 is plausibly noise; 2 in
 * a 10k-iter window is a real correlation. */
#define CANARY_CRASH_THRESHOLD		2U

/* CANARY_BACKOFF_TIME lives in child-canary-internal.h -- shared with
 * the picker's DEMOTED-state backoff check. */

/* CANARY_SETUP_BROKEN_FAILS moved to child-canary-picker.c (only user
 * is canary_queue_tick()'s early-bail branch). */

/* CANARY_SETUP_BROKEN_BACKOFF_TIME lives in child-canary-internal.h --
 * shared with the picker's DEMOTED-state backoff check. */

/* Consecutive 100%-setup-failure windows before an op is auto-transitioned
 * out of the retry-with-backoff loop and into terminal CONFIG_BLOCKED.
 * Three windows means ~12 h of retry (three CANARY_SETUP_BROKEN_BACKOFF_
 * TIME waits) before the queue gives up: generous enough that a transient
 * module load / mount race does not eat the slot, short enough that a
 * genuinely absent host prereq stops burning canary budget within a
 * working day.  Consecutive count is reset by any non-setup-broken window
 * outcome (promote, crash_threshold, zero_edges, ineligible), so an op
 * that transiently misbehaves but later recovers never reaches the cap. */
#define CANARY_SETUP_BROKEN_AUTOBLOCK_N	3U

/* Cap on the number of no-PC-bracket retries close_window_and_decide()
 * will spend on a single op before allowing the demote-for-productivity
 * path to fire.  A "no-PC-bracket window" is one whose attempts_delta
 * > 0 but bracketed_delta == 0 -- every dispatch hit an outer-bracket
 * reject arm, dominantly KCOV_MODE_CMP.  Each retry re-enters
 * enter_canarying(), which kills the slot children so their respawn
 * re-draws kcov mode and a subsequent window has another chance to
 * land on a PC-mode child.  With KCOV_CMP_CHILD_RECIPROCAL=4 and one
 * canary slot P(all-CMP window) ~= 25%; a cap of 3 retries requires
 * four consecutive bad windows to trigger a demote (~0.4% false-
 * negative rate) and terminates on a truly PC-hostile config. */
#define CANARY_PC_TRIAL_RETRIES_MAX	3U

/* CANARY_WEDGE_STALL_SEC moved to child-canary-picker.c (only user is
 * canary_queue_tick()'s wedge-stall bail-out branch). */

/* CANARY_PROMOTION_RING_SIZE lives in child-canary-internal.h -- the
 * promotion ring itself is owned by the report TU. */

/* Per-window deltas at or above which a promotion is tagged as
 * "state-corrupting" in the promotion log line.  Inputs are fleet-
 * wide cumulative counters (parent_stats.{post_handler_corrupt_ptr,
 * deferred_free_reject}), so the delta is a coincidence signal, not
 * a per-op attribution: every running child contributes.  Thresholds
 * are intentionally loose to start; the tag is observability-only
 * and re-tuning is cheap once a baseline distribution exists in the
 * field.  Treat a tagged promotion as "look at this one", not
 * "block this one". */
#define CANARY_HEALTH_CORRUPT_PTR_THRESHOLD	50UL
#define CANARY_HEALTH_DEFERRED_FREE_THRESHOLD	50UL

/* CANARY_SUMMARY_INTERVAL_SEC moved to child-canary-report.c alongside
 * canary_queue_summary(). */

/* Priority seed list and skip sets: canary_priority_seeds[],
 * canary_config_blocked[], canary_pid_heavy_ops[], canary_risky_defer[]
 * moved to child-canary-policy.c.  These are the operator-visible
 * inputs to the queue's picker order. */

/* --------------------------------------------------------------------
 * Per-op queue state.  Parent-private; indexed by child_op_type enum.
 * -------------------------------------------------------------------- */

struct canary_op_state canary_ops[NR_CHILD_OP_TYPES];

/* Picker cursors (canary_priority_cursor, canary_fifo_cursor), the
 * resolved priority-list pointer + count (canary_priority_list,
 * canary_priority_list_count), and the --canary-seed widened backing
 * storage (canary_seed_override_widened[]) moved to
 * child-canary-picker.c. */

/* Active op the canary slot(s) should be running right now.  Two-stage
 * commit: enter_canarying() writes canary_pending_op and stamps the
 * window-start counters, but canary_active_op_cell is only flipped
 * when canary_queue_on_child_respawn() fires -- the slot's previous
 * child has actually exited and a fresh one has been forked with the
 * new op.  Straggler iterations of the old op therefore do not
 * pollute the new op's window edges/crashes counters. */
enum child_op_type canary_active_op_cell = CHILD_OP_SYSCALL;
enum child_op_type canary_pending_op = CHILD_OP_SYSCALL;
bool canary_active_op_set = false;
bool canary_pending_op_set = false;

/* Parked state: when canary_queue_tick() finds the picker exhausted
 * (no eligible candidate after the active window closes), the queue
 * has no op to run on the canary slot(s) but the slot children are
 * still alive with the just-demoted/finished op stamped from a prior
 * spawn.  Dedicated alt-op children keep child->op_type for life, so
 * without intervention the demoted op keeps executing on the slot --
 * and crashes from it are dropped because canary_active_op_set is
 * false.  Parking the slot stamps it with CHILD_OP_SYSCALL on the
 * next respawn (the canary path still wins in assign_dedicated_alt_op
 * because canary_slot_active() returns true while parked), so the
 * slot drops back to the default syscall picker until the next canary
 * cycle stages a new pending op via enter_canarying(). */
bool canary_slots_parked = false;

/* True once the queue is fully initialised AND not gated off by
 * --no-canary-queue / canary_slots=0.  When false, every public entry
 * point returns immediately and the dormant gate is consulted as a
 * historical static vector. */
bool canary_queue_live = false;

/* Recently-promoted ring (canary_promotion_ring[] + head/count) and the
 * canary_last_summary throttle timestamp moved to child-canary-report.c;
 * push_promotion() lives there too. */

/* canary_last_plateau moved to child-canary-picker.c (only user is
 * log_plateau_edge()). */

/* Per-op latch set by leave_canarying_demote_setup_broken() to mark an op
 * whose last demotion was for 100%-setup-failure shape.  Read by the
 * picker's DEMOTED-state backoff check, which then uses
 * CANARY_SETUP_BROKEN_BACKOFF_TIME instead of CANARY_BACKOFF_TIME.
 * Cleared in enter_canarying() so a re-canary that survives (or hits a
 * different demote reason) drops back to the normal backoff schedule. */
bool canary_op_setup_broken[NR_CHILD_OP_TYPES];

/* --------------------------------------------------------------------
 * Helpers.
 * -------------------------------------------------------------------- */

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

/* Returns a short static string naming the kcov_bracket_begin() reject
 * arm this op has hit at least once, or NULL if no skip reason applies.
 *
 * Priority order mirrors the decision tree in kcov_bracket_begin()
 * (kcov/enable.c): inactive > cmp-mode > nested.  The check is
 * intentionally "any skip > 0" rather than "all attempts skipped"
 * because the confound the caller is guarding against is "the outer
 * bracket cannot see this op's clean edges at all" -- for a
 * KCOV_MODE_CMP child that is true for every single dispatch, and one
 * observation is enough to explain a childop_edges_clean[op] == 0
 * window.  Consumers gate on this AFTER already confirming clean==0
 * so the combined test remains conservative. */
static const char *op_kcov_skip_reason(enum child_op_type op)
{
	if (kcov_shm == NULL || (unsigned int)op >= KCOV_CHILDOP_NR_MAX)
		return NULL;
	if (__atomic_load_n(&kcov_shm->childop_kcov.childop_kcov_op_skipped_inactive[op],
			    __ATOMIC_RELAXED) > 0)
		return "kcov_bracket_inactive";
	if (__atomic_load_n(&kcov_shm->childop_kcov.childop_kcov_op_skipped_cmp[op],
			    __ATOMIC_RELAXED) > 0)
		return "kcov_mode_cmp";
	if (__atomic_load_n(&kcov_shm->childop_kcov.childop_kcov_op_skipped_nested[op],
			    __ATOMIC_RELAXED) > 0)
		return "kcov_bracket_nested";
	return NULL;
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

/* fork_pressure_should_suppress() and the op_is_in_table() dead-code
 * helper moved to child-canary-policy.c alongside canary_pid_heavy_ops[]. */

/* Setup-failure reason table (struct canary_setup_reason_hint,
 * canary_setup_reason_hints[], canary_setup_fail_reason_name(),
 * canary_setup_fail_reason_for_op()) moved to child-canary-policy.c. */

/* --------------------------------------------------------------------
 * State transitions.
 * -------------------------------------------------------------------- */

/*
 * Three-stage teardown: request graceful exit via SIGTERM, give slots a
 * brief grace window to drop locks / finish cleanup, then SIGKILL any
 * that ignored the request.  kill_pid() itself is SIGKILL-only by
 * contract, so stage 1 uses kill(pid, SIGTERM) directly; stage 3
 * routes through kill_pid() to inherit its mainpid / pid_is_valid
 * safety guards.  Slot pids are re-read on every pass because the
 * main reaper races us.
 */
#define CANARY_SIGTERM_GRACE_ITERS	20
#define CANARY_SIGTERM_GRACE_USLEEP	1000

void kill_canary_slot_children(void)
{
	unsigned int i, iter;
	unsigned int n = canary_slots;

	if (n > max_children)
		n = max_children;

	/* Shutdown stage 1: request graceful exit. */
	for (i = 0; i < n; i++) {
		pid_t pid = __atomic_load_n(&pids[i], __ATOMIC_ACQUIRE);

		if (pid == EMPTY_PIDSLOT || pid <= 0)
			continue;
		if (pid == mainpid)
			continue;
		kill(pid, SIGTERM);
	}

	/* Shutdown stage 2: ~20 ms grace window, polling for liveness only.  We
	 * must NOT waitpid() the canary child here -- the parent's main
	 * reaper owns that path and is what updates pids[]/running_childs
	 * via reap_child().  A self-reap in this loop would race the main
	 * reaper, which then sees ECHILD and leaves the slot parked in
	 * the deferred-recovery window for ~30-40s.  kill(pid, 0) treats
	 * a not-yet-reaped zombie as still alive, which is exactly what
	 * we want: we keep waiting until the main reaper has fully torn
	 * the task down. */
	for (iter = 0; iter < CANARY_SIGTERM_GRACE_ITERS; iter++) {
		bool any_alive = false;

		for (i = 0; i < n; i++) {
			pid_t pid = __atomic_load_n(&pids[i], __ATOMIC_ACQUIRE);

			if (pid == EMPTY_PIDSLOT || pid <= 0)
				continue;
			if (kill(pid, 0) == -1 && errno == ESRCH)
				continue;
			any_alive = true;
		}
		if (!any_alive)
			return;
		usleep(CANARY_SIGTERM_GRACE_USLEEP);
	}

	/* Shutdown stage 3: SIGKILL anything still alive. */
	for (i = 0; i < n; i++) {
		pid_t pid = __atomic_load_n(&pids[i], __ATOMIC_ACQUIRE);

		if (pid != EMPTY_PIDSLOT && pid > 0)
			kill_pid(pid);
	}
}

void enter_canarying(enum child_op_type op)
{
	struct canary_op_state *s;
	time_t now = monotonic_seconds();

	if (op == CHILD_OP_SYSCALL || op >= NR_CHILD_OP_TYPES)
		return;

	/* Re-canary: drop any prior setup-broken latch so this window is
	 * scored on its own outcome.  If setup is still broken the flag
	 * gets re-set by leave_canarying_demote_setup_broken(); if not,
	 * any later demote falls back to the normal CANARY_BACKOFF_TIME. */
	canary_op_setup_broken[op] = false;

	s = &canary_ops[op];
	s->state = CANARY_STATE_CANARYING;
	s->window_crashes = 0;
	/* Reset the per-signature breakdown table alongside the scalar
	 * total so a fresh window scores its own {signo, sig_code,
	 * fault_ip} distribution rather than carrying prior-window shapes
	 * into the demote/promote log line. */
	memset(s->window_crash_sigs, 0, sizeof(s->window_crash_sigs));
	s->window_crash_sigs_count = 0;
	s->window_crash_sigs_overflow = 0;
	s->window_start_invocations = invocations_for_op(op);
	s->window_start_edges = edges_for_op(op);
	s->window_start_post_handler_corrupt_ptr =
		parent_stats.post_handler_corrupt_ptr;
	s->window_start_deferred_free_reject =
		parent_stats.deferred_free_reject;
	s->window_start_kcov_first_ebadf_op_nr = kcov_shm
		? __atomic_load_n(&kcov_shm->pc_diag.first_ebadf_op_nr,
				  __ATOMIC_RELAXED)
		: 0;

	/* SHADOW per-window baselines for the score-driven recommended-
	 * state computation in close_window_and_decide().  Read the same
	 * shm counters the foundation childop_outcome_snapshot() consumes,
	 * so the per-window deltas line up with the cumulative outcome
	 * record's field semantics.  Telemetry-only; no live decision
	 * reads these. */
	{
		unsigned long discovered = __atomic_load_n(
			&shm->stats.childop.edges_discovered[op],
			__ATOMIC_RELAXED);
		unsigned long clean = __atomic_load_n(
			&shm->stats.childop.edges_clean[op],
			__ATOMIC_RELAXED);
		unsigned long setup_accepted = __atomic_load_n(
			&shm->stats.childop.setup_accepted[op],
			__ATOMIC_RELAXED);
		unsigned long invocations_now = __atomic_load_n(
			&shm->stats.childop.invocations[op],
			__ATOMIC_RELAXED);

		s->window_start_noisy_edges = (discovered > clean)
			? (discovered - clean) : 0;
		s->window_start_wedges = __atomic_load_n(
			&shm->stats.childop.wedge_count[op],
			__ATOMIC_RELAXED);
		s->window_start_setup_accepted = setup_accepted;
		s->window_start_setup_failures = (invocations_now > setup_accepted)
			? (invocations_now - setup_accepted) : 0;
		s->window_start_wall_ns = __atomic_load_n(
			&shm->stats.childop.wall_ns[op],
			__ATOMIC_RELAXED);
	}

	/* Snapshots for the PC-trial retry gate in close_window_and_decide().
	 * The delta at window close tells whether ANY canary-slot dispatch of
	 * this op opened an outer PC bracket during the window; if not, the
	 * clean-edges signal was uninformative and the demote decision is
	 * deferred for up to CANARY_PC_TRIAL_RETRIES_MAX retries. */
	s->window_start_kcov_op_attempts = kcov_shm
		? __atomic_load_n(
			&kcov_shm->childop_kcov.childop_kcov_op_attempts[op],
			__ATOMIC_RELAXED)
		: 0;
	/* Per-reason snapshots.  Close-time deltas let the retry gate
	 * label the window by rejection reason: the CMP arm is retry-
	 * eligible (re-drawing the kcov mode can land a PC-mode child
	 * next window), the nested arm is a lifecycle-invariant violation
	 * (caller-side bug -- retry cannot help; reported instead), and
	 * the inactive arm reflects a run-wide config a retry cannot
	 * turn on.  Only "skipped_cmp_delta == attempts_delta" windows
	 * are eligible for the pre-demote PC-trial retry. */
	s->window_start_kcov_op_skipped_cmp = kcov_shm
		? __atomic_load_n(
			&kcov_shm->childop_kcov.childop_kcov_op_skipped_cmp[op],
			__ATOMIC_RELAXED)
		: 0;
	s->window_start_kcov_op_skipped_nested = kcov_shm
		? __atomic_load_n(
			&kcov_shm->childop_kcov.childop_kcov_op_skipped_nested[op],
			__ATOMIC_RELAXED)
		: 0;
	s->window_start_kcov_op_skipped_inactive = kcov_shm
		? __atomic_load_n(
			&kcov_shm->childop_kcov.childop_kcov_op_skipped_inactive[op],
			__ATOMIC_RELAXED)
		: 0;

	s->last_canary_window_start = now;
	s->last_state_transition = now;
	s->canary_iterations++;

	/* Flip the gate so the random alt-op picker (and the dedicated-
	 * canary-slot stamping path) starts including this op. */
	dormant_op_set(op, false);

	/* Per-window entry announcement.  s->canary_iterations is the
	 * lifetime count of canary windows opened for this op (just
	 * bumped above), so #1 is the very first canary, #2 a re-canary
	 * after a demoted backoff, etc.  The 1/<budget> reflects in-
	 * window iter progress, which is 1 at entry. */
	output(0, "canary: %s entering window 1/%u iters (canary iteration #%u)\n",
		s->name, window_iters_resolved(), s->canary_iterations);

	/* Stage the new op as the pending canary; the next respawn of a
	 * canary slot commits it as the active op.  Force a respawn now
	 * by killing any current canary-slot child so the new op picks up
	 * quickly. */
	canary_pending_op = op;
	canary_pending_op_set = true;
	/* Leaving the parked state -- a new pending op is staged. */
	canary_slots_parked = false;
	kill_canary_slot_children();
}

/* Classify a just-finished canary window into a coarse health
 * verdict, computed from per-window deltas of the three fleet-wide
 * defence counters captured at window open in enter_canarying().
 *
 * Verdict precedence (most severe wins):
 *   "KCOV-damaging"    -- kcov_shm->pc_diag.first_ebadf_op_nr was 0
 *                         at window open and is non-zero at window
 *                         close.  Means the first kcov_enable_trace
 *                         EBADF observed in this run was first seen
 *                         during this op's canary window; the
 *                         first-failure-wins gate latches once, so a
 *                         later non-zero observation does not retag.
 *   "state-corrupting" -- corrupt_ptr_delta or deferred_free_delta
 *                         crossed its threshold during the window.
 *                         Inputs are fleet-wide so this is a
 *                         coincidence tag (any sibling can have
 *                         driven the delta), not attribution.
 *   "clean"            -- otherwise.
 *
 * The "leak-associated" class from the spec is unimplemented: there
 * is no per-canary-window kmemleak growth counter in the tree today.
 * The deltas themselves are returned through the *_out pointers so
 * the caller can include the raw numbers in the promotion log line
 * for forensic value. */
static const char *canary_health_verdict(const struct canary_op_state *s,
					 unsigned long *corrupt_ptr_delta_out,
					 unsigned long *deferred_free_delta_out,
					 bool *kcov_ebadf_in_window_out)
{
	unsigned long now_corrupt = parent_stats.post_handler_corrupt_ptr;
	unsigned long now_deferred = parent_stats.deferred_free_reject;
	unsigned long now_ebadf = kcov_shm
		? __atomic_load_n(&kcov_shm->pc_diag.first_ebadf_op_nr,
				  __ATOMIC_RELAXED)
		: 0;
	unsigned long corrupt_delta = (now_corrupt >= s->window_start_post_handler_corrupt_ptr)
		? (now_corrupt - s->window_start_post_handler_corrupt_ptr) : 0;
	unsigned long deferred_delta = (now_deferred >= s->window_start_deferred_free_reject)
		? (now_deferred - s->window_start_deferred_free_reject) : 0;
	bool ebadf_in_window =
		(s->window_start_kcov_first_ebadf_op_nr == 0) && (now_ebadf != 0);

	*corrupt_ptr_delta_out = corrupt_delta;
	*deferred_free_delta_out = deferred_delta;
	*kcov_ebadf_in_window_out = ebadf_in_window;

	if (ebadf_in_window)
		return "KCOV-damaging";
	if (corrupt_delta >= CANARY_HEALTH_CORRUPT_PTR_THRESHOLD ||
	    deferred_delta >= CANARY_HEALTH_DEFERRED_FREE_THRESHOLD)
		return "state-corrupting";
	return "clean";
}

static void leave_canarying_promote(enum child_op_type op,
				    unsigned long window_iters,
				    unsigned long window_edges)
{
	struct canary_op_state *s = &canary_ops[op];
	unsigned long corrupt_delta = 0;
	unsigned long deferred_delta = 0;
	bool ebadf_in_window = false;
	const char *verdict;

	s->state = CANARY_STATE_PROMOTED;
	s->last_state_transition = monotonic_seconds();
	s->total_promotions++;
	/* Non-setup-broken outcome resets the consecutive counter so a
	 * recovered op does not carry old setup-failure credit into a
	 * later re-canary. */
	s->consecutive_setup_broken = 0;
	/* Terminal outcome: clear the PC-trial retry streak so a later
	 * re-canary (after backoff / re-queue) starts fresh. */
	s->consecutive_no_pc_bracket = 0;
	push_promotion(op);

	/* Gate stays at 0 (active).  The random picker keeps the op. */
	dormant_op_set(op, false);

	verdict = canary_health_verdict(s, &corrupt_delta, &deferred_delta,
					&ebadf_in_window);

	/* Observability-only: the verdict is appended to the existing
	 * promotion log so operators can correlate the latest promotion
	 * with a coincident defence-counter spike.  The deltas are
	 * fleet-wide (see comment on canary_op_state snapshot fields and
	 * canary_health_verdict above), so the tag flags a window for
	 * inspection -- it does not gate scheduling. */
	output(0, "canary: %s promoted (window edges=%lu crashes=%u in %lu iters; health=%s corrupt_ptr_delta=%lu deferred_free_delta=%lu kcov_first_ebadf_in_window=%d; deltas are fleet-wide, not per-op attributed; effective for new children at next respawn)\n",
		s->name, window_edges, s->window_crashes, window_iters,
		verdict, corrupt_delta, deferred_delta,
		ebadf_in_window ? 1 : 0);

	/* Crash-signature breakdown, keyed on {signo, sig_code, enclosing-
	 * function fault_ip}.  Emitted only when at least one crash was
	 * observed so a clean window stays quiet.  A promotion with N>0
	 * crashes is legitimate (edges >= threshold outweighs crashes <
	 * threshold), and knowing which shape those crashes had is
	 * exactly what turns a "17 code-2 + 13 code-1 + 3 code-128" mix
	 * back into three actionable signatures. */
	if (s->window_crash_sigs_count > 0 || s->window_crash_sigs_overflow > 0) {
		char sigbuf[512];
		canary_crash_sig_render(op, sigbuf, sizeof(sigbuf));
		output(0, "canary: %s crash-signatures: %s\n", s->name, sigbuf);
	}
}

/* noisy_edges_delta is the window's accrual of sibling-attributed /
 * unattributable edges (childop_edges_discovered[op] -
 * childop_edges_clean[op] delta over the window).  Surfaced in the
 * demote log so a reader can tell a "ran and produced nothing"
 * zero_edges close (clean=0, noisy=0) apart from a "ran and only saw
 * sibling interference" close (clean=0, noisy>0) -- the latter is the
 * shadow-policy PROMOTED_INTERFERENCE shape that the live decision
 * still demotes under "zero_edges".  The two outcomes warrant different
 * triage but the legacy log line collapsed them.  Reason-agnostic so
 * the crash_threshold path also surfaces the value for context. */
static void leave_canarying_demote(enum child_op_type op,
				   const char *reason,
				   unsigned long window_iters,
				   unsigned long window_edges,
				   unsigned long noisy_edges_delta)
{
	struct canary_op_state *s = &canary_ops[op];

	s->state = CANARY_STATE_DEMOTED;
	s->last_state_transition = monotonic_seconds();
	s->total_demotions++;
	/* Non-setup-broken outcome: reset the consecutive setup-broken
	 * counter.  An op that hit crash_threshold or zero_edges is not
	 * on the auto-block track. */
	s->consecutive_setup_broken = 0;
	/* Terminal outcome: clear the PC-trial retry streak. */
	s->consecutive_no_pc_bracket = 0;

	/* Flip the gate back to dormant so the random picker stops
	 * including this op. */
	dormant_op_set(op, true);

	output(0, "canary: %s demoted (reason: %s; edges=%lu noisy_edges_seen=%lu crashes=%u in %lu iters; backoff=%us; effective for new children at next respawn)\n",
		s->name, reason, window_edges, noisy_edges_delta,
		s->window_crashes, window_iters,
		(unsigned int)CANARY_BACKOFF_TIME);

	/* Same crash-signature breakdown attached to leave_canarying_promote:
	 * a demote for reason=crash_threshold is the exact case where
	 * "17 code-2 + 13 code-1 + 3 code-128" being reported as a single
	 * "crashes=33" number misleads triage.  Print the per-{signo,
	 * sig_code, fault_ip} breakdown so distinct death classes stay
	 * distinct in the log.  Skipped when the window closed with zero
	 * crashes (reason=zero_edges / kcov_mode_cmp etc.) so a clean
	 * window stays quiet. */
	if (s->window_crash_sigs_count > 0 || s->window_crash_sigs_overflow > 0) {
		char sigbuf[512];
		canary_crash_sig_render(op, sigbuf, sizeof(sigbuf));
		output(0, "canary: %s crash-signatures: %s\n", s->name, sigbuf);
	}
}

/* Early-bail demote: the op has burned CANARY_SETUP_BROKEN_FAILS setup
 * failures inside the current window without a single setup success, so
 * its setup path is structurally broken (a code-fix problem, not a
 * coverage one).  Demote with a louder log and the longer
 * CANARY_SETUP_BROKEN_BACKOFF_TIME so the picker stops re-spending
 * window budget on it every 30 minutes.  The op stays in DEMOTED state
 * (the picker honours the longer backoff via canary_op_setup_broken[]),
 * so a re-canary path still exists -- a fix that lands while the run
 * continues will be re-evaluated at the longer cadence.
 *
 * Distinction from "zero_edges": zero_edges means the op RAN to
 * completion and produced no new clean edges (low-value, may self-heal);
 * SETUP_BROKEN means the op NEVER ran a successful setup (broken, needs
 * code fix).  Keeping the reasons separate lets the operator triage them
 * differently. */
void leave_canarying_demote_setup_broken(enum child_op_type op,
					 unsigned long window_iters,
					 unsigned long setup_failures)
{
	struct canary_op_state *s = &canary_ops[op];
	enum canary_setup_fail_reason reason = canary_setup_fail_reason_for_op(op);

	s->consecutive_setup_broken++;
	s->setup_fail_reason = reason;
	s->last_state_transition = monotonic_seconds();
	s->total_demotions++;
	/* Terminal outcome for the PC-trial streak: a broken setup path
	 * will never open a PC bracket regardless of kcov mode, so any
	 * accumulated no-PC-bracket count is not the reason we bailed. */
	s->consecutive_no_pc_bracket = 0;

	/* Flip the gate back to dormant so the random picker stops
	 * including this op. */
	dormant_op_set(op, true);

	/* Auto-block: after N consecutive 100%-setup-failure windows the
	 * op is treated as structurally unrunnable on this host and
	 * transitioned into the existing CONFIG_BLOCKED state.  The picker
	 * skips CONFIG_BLOCKED ops (see pick_next_canary), so this ends
	 * the retry loop -- no more slot budget is spent on the op for
	 * the remainder of the run.  The setup_broken latch is dropped
	 * here because the DEMOTED-backoff path is no longer used. */
	if (s->consecutive_setup_broken >= CANARY_SETUP_BROKEN_AUTOBLOCK_N) {
		s->state = CANARY_STATE_CONFIG_BLOCKED;
		s->blocked_reason = CANARY_BLOCKED_REASON_SETUP_BROKEN;
		canary_op_setup_broken[op] = false;
		output(0, "canary: %s AUTO-BLOCKED after %u consecutive 100%% setup-failure windows (reason: %s, last setup_failures=%lu in %lu iters); terminal, no further re-canary; effective for new children at next respawn\n",
			s->name, s->consecutive_setup_broken,
			canary_setup_fail_reason_name(reason),
			setup_failures, window_iters);
		return;
	}

	s->state = CANARY_STATE_DEMOTED;
	canary_op_setup_broken[op] = true;

	/* Loud log: operator-facing call to action, distinct from the
	 * routine "demoted (reason: zero_edges ...)" line so a grep for
	 * BROKEN-SETUP surfaces only the structural-failure cases. */
	output(0, "canary: %s BROKEN-SETUP: 100%% setup failure (reason: %s, setup_failures=%lu, setup_ok=0 in %lu iters; consecutive_setup_broken=%u/%u) -- fix this op; backoff=%us before re-test; effective for new children at next respawn\n",
		s->name, canary_setup_fail_reason_name(reason),
		setup_failures, window_iters,
		s->consecutive_setup_broken,
		CANARY_SETUP_BROKEN_AUTOBLOCK_N,
		(unsigned int)CANARY_SETUP_BROKEN_BACKOFF_TIME);
}

/* Wedge-stall demote: the canary window has been open for
 * CANARY_WEDGE_STALL_SEC without a single op_fn return, so every
 * dispatched child is hanging inside the op's kernel path long enough
 * that the parent watchdog kills it before the invocation-count bump
 * at op_fn's return.  Distinct from setup_broken (which requires
 * invocations > 0 to observe a non-zero setup_fail_delta) and from
 * zero_edges (which requires the window to have completed budget
 * iters).  Re-use the setup_broken latch so the demote inherits the
 * longer CANARY_SETUP_BROKEN_BACKOFF_TIME -- a childop whose op_fn
 * never returns needs a code fix (to the op or to the kernel), not a
 * 30-minute wait. */
void leave_canarying_demote_wedged(enum child_op_type op,
				   time_t window_age_sec)
{
	struct canary_op_state *s = &canary_ops[op];

	s->state = CANARY_STATE_DEMOTED;
	s->last_state_transition = monotonic_seconds();
	s->total_demotions++;
	canary_op_setup_broken[op] = true;
	/* Wedge is a distinct failure mode from setup-broken, so a
	 * wedged close breaks any "consecutive setup-broken" streak. */
	s->consecutive_setup_broken = 0;
	/* Wedged op_fn calls never reach the outer PC-bracket close either,
	 * so the PC-trial retry streak is irrelevant here -- clear it. */
	s->consecutive_no_pc_bracket = 0;

	/* Flip the gate back to dormant so the random picker stops
	 * including this op. */
	dormant_op_set(op, true);

	output(0, "canary: %s WEDGED: no op_fn return in %llds (every child killed by parent watchdog before op_fn could bump invocations) -- fix this op; backoff=%us before re-test; effective for new children at next respawn\n",
		s->name, (long long)window_age_sec,
		(unsigned int)CANARY_SETUP_BROKEN_BACKOFF_TIME);
}

/* Terminal exit for structurally canary-ineligible ops: those for
 * which op_uses_outer_bracket(op) is false and therefore whose
 * childop_edges_clean[op] slot is permanently zero (the outer KCOV
 * bracket cannot wrap their dispatch shape).  Reading the clean
 * counter at window close yields no signal -- not "zero yield" --
 * so this path is distinct from leave_canarying_demote("zero_edges"):
 * it is NOT a verdict on the op's usefulness, just an acknowledgement
 * that the canary mechanism's signal source is unavailable for it.
 *
 * Transition to CONFIG_BLOCKED (terminal, never re-picked) so the
 * queue does not loop the op back through the same false-signal
 * window every CANARY_BACKOFF_TIME seconds.  total_demotions is NOT
 * bumped (no penalty).  The dormant gate is restored to off, undoing
 * enter_canarying()'s turn-on -- without a yield signal we have no
 * justification to leave the op active by default. */
static void leave_canarying_ineligible(enum child_op_type op,
				       unsigned long window_iters,
				       unsigned long window_edges)
{
	struct canary_op_state *s = &canary_ops[op];

	s->state = CANARY_STATE_CONFIG_BLOCKED;
	s->blocked_reason = CANARY_BLOCKED_REASON_NO_OUTER_BRACKET;
	s->last_state_transition = monotonic_seconds();
	s->consecutive_setup_broken = 0;
	/* Terminal outcome: no further re-canary, so any accumulated
	 * PC-trial retry streak is moot -- clear it. */
	s->consecutive_no_pc_bracket = 0;

	dormant_op_set(op, true);

	output(0, "canary: %s canary-ineligible (reason: no outer bracket; edges=%lu crashes=%u in %lu iters; terminal, no backoff retry; effective for new children at next respawn)\n",
		s->name, window_edges, s->window_crashes, window_iters);
}

/* pick_next_canary() moved to child-canary-picker.c. */

/* --------------------------------------------------------------------
 * Shadow recommendation: telemetry-only score-driven verdict on the
 * just-closed canary window.  Computed alongside the live decision
 * below; never replaces it.  Bumps shm->stats.childop.would_demote /
 * childop_would_promote and emits one canary_shadow log line so the
 * operator (and the 75.2.B enforcement work) can see how often the
 * score-driven verdict would diverge from the live one before the
 * picker is rewired.
 *
 * Recommendation precedence:
 *   NO_OUTER_BRACKET dispatch shape has no outer KCOV bracket.
 *                    NOT a host-config failure: the op still runs, it
 *                    just cannot populate clean-edge attribution.
 *   QUARANTINED      crash threshold tripped AND the op has been
 *                    demoted at least once already (repeated bad
 *                    windows).
 *   THROTTLED        crash threshold tripped on the first bad window,
 *                    OR clean / noisy both zero with a wedge in the
 *                    window.
 *   PROMOTED_CLEAN   clean edges crossed CANARY_EDGE_THRESHOLD.
 *   PROMOTED_INTERFERENCE
 *                    clean signal weak (below threshold) but noisy
 *                    edges accrued during the window.  This is the new
 *                    state the rewrite adds; the live decision demotes
 *                    on "zero_edges" instead.
 *   CANARY_CLEAN     otherwise (keep canarying; benign zero window).
 */
static enum childop_recommended_state
canary_recommend_state(enum child_op_type op,
		       unsigned long clean_edges_delta,
		       unsigned long noisy_edges_delta,
		       unsigned long wedges_delta,
		       unsigned int window_crashes,
		       unsigned int prior_demotions)
{
	if (!op_uses_outer_bracket(op))
		return CHILDOP_REC_NO_OUTER_BRACKET;
	if (window_crashes >= CANARY_CRASH_THRESHOLD) {
		if (prior_demotions > 0)
			return CHILDOP_REC_QUARANTINED;
		return CHILDOP_REC_THROTTLED;
	}
	if (clean_edges_delta >= CANARY_EDGE_THRESHOLD)
		return CHILDOP_REC_PROMOTED_CLEAN;
	if (clean_edges_delta == 0 && noisy_edges_delta > 0) {
		/* Discovered grew without clean growing.  If a
		 * kcov_bracket_begin() skip reason for THIS op is on
		 * record, the clean/noisy split is a MODE ARTIFACT of the
		 * PC-bracket rejection (KCOV_MODE_CMP children never open
		 * an outer PC bracket, so every clean=0 window on them is
		 * confounded) -- not a "sibling interference only" signal
		 * the operator can promote on.  Route to the explicit
		 * unattributed_edges state so neither would_promote nor
		 * would_demote is bumped for this window.  Without a skip
		 * reason the original PROMOTED_INTERFERENCE recommendation
		 * still stands. */
		if (op_kcov_skip_reason(op) != NULL)
			return CHILDOP_REC_UNATTRIBUTED_EDGES;
		return CHILDOP_REC_PROMOTED_INTERFERENCE;
	}
	if (clean_edges_delta == 0 && noisy_edges_delta == 0 &&
	    wedges_delta > 0)
		return CHILDOP_REC_THROTTLED;
	return CHILDOP_REC_CANARY_CLEAN;
}

const char *childop_recommended_state_name(enum childop_recommended_state s)
{
	switch (s) {
	case CHILDOP_REC_DORMANT:		return "DORMANT";
	case CHILDOP_REC_CANARY_CLEAN:		return "CANARY_CLEAN";
	case CHILDOP_REC_PROMOTED_CLEAN:	return "PROMOTED_CLEAN";
	case CHILDOP_REC_PROMOTED_INTERFERENCE:	return "PROMOTED_INTERFERENCE";
	case CHILDOP_REC_THROTTLED:		return "THROTTLED";
	case CHILDOP_REC_QUARANTINED:		return "QUARANTINED";
	case CHILDOP_REC_NO_OUTER_BRACKET:	return "NO_OUTER_BRACKET";
	case CHILDOP_REC_UNATTRIBUTED_EDGES:	return "UNATTRIBUTED_EDGES";
	}
	return "UNKNOWN";
}

static bool recommended_state_is_promote(enum childop_recommended_state s)
{
	/* CHILDOP_REC_UNATTRIBUTED_EDGES is intentionally NOT in this
	 * set: the clean/noisy split it keys off is a MODE ARTIFACT of
	 * the outer PC bracket getting rejected (see canary_recommend_
	 * state()), so promoting on that signal would be promoting on
	 * confounded data.  Left explicit to make the exclusion visible. */
	return s == CHILDOP_REC_PROMOTED_CLEAN ||
	       s == CHILDOP_REC_PROMOTED_INTERFERENCE;
}

static bool recommended_state_is_demote(enum childop_recommended_state s)
{
	/* CHILDOP_REC_UNATTRIBUTED_EDGES is intentionally NOT in this
	 * set either: without a bracketed clean signal we cannot tell
	 * whether the op is productive or not, so we neither reward nor
	 * penalise it in the shadow tallies.  The live path still
	 * demotes for backoff (leave_canarying_demote with the specific
	 * skip-reason string), which is a separate decision made in
	 * close_window_and_decide(). */
	return s == CHILDOP_REC_THROTTLED ||
	       s == CHILDOP_REC_QUARANTINED ||
	       s == CHILDOP_REC_NO_OUTER_BRACKET;
}

/* --------------------------------------------------------------------
 * Window close: called from the tick once enough iterations have
 * elapsed against the active canary op.
 * -------------------------------------------------------------------- */

void close_window_and_decide(enum child_op_type op)
{
	struct canary_op_state *s = &canary_ops[op];
	unsigned long now_invocations = invocations_for_op(op);
	unsigned long now_edges = edges_for_op(op);
	unsigned long iters = (now_invocations >= s->window_start_invocations)
		? (now_invocations - s->window_start_invocations) : 0;
	unsigned long edges = (now_edges >= s->window_start_edges)
		? (now_edges - s->window_start_edges) : 0;

	/* SHADOW per-window deltas for the score-driven recommended-state
	 * computation.  Read AFTER the live deltas above so a relaxed-load
	 * race between the two paths only ever advances the shadow view
	 * past the live view, never the other way round.  Computed and
	 * logged ALONGSIDE the live decision below; the live branches stay
	 * byte-identical to the pre-shadow baseline. */
	unsigned long now_discovered = __atomic_load_n(
		&shm->stats.childop.edges_discovered[op], __ATOMIC_RELAXED);
	unsigned long now_clean = now_edges;
	unsigned long now_noisy = (now_discovered > now_clean)
		? (now_discovered - now_clean) : 0;
	unsigned long noisy_delta = (now_noisy > s->window_start_noisy_edges)
		? (now_noisy - s->window_start_noisy_edges) : 0;
	unsigned long now_wedges = __atomic_load_n(
		&shm->stats.childop.wedge_count[op], __ATOMIC_RELAXED);
	unsigned long wedges_delta = (now_wedges > s->window_start_wedges)
		? (now_wedges - s->window_start_wedges) : 0;
	unsigned long now_setup_accepted = __atomic_load_n(
		&shm->stats.childop.setup_accepted[op], __ATOMIC_RELAXED);
	unsigned long setup_ok_delta =
		(now_setup_accepted > s->window_start_setup_accepted)
		? (now_setup_accepted - s->window_start_setup_accepted) : 0;
	unsigned long now_setup_failures =
		(now_invocations > now_setup_accepted)
		? (now_invocations - now_setup_accepted) : 0;
	unsigned long setup_fail_delta =
		(now_setup_failures > s->window_start_setup_failures)
		? (now_setup_failures - s->window_start_setup_failures) : 0;
	unsigned long now_wall_ns = __atomic_load_n(
		&shm->stats.childop.wall_ns[op], __ATOMIC_RELAXED);
	unsigned long wall_ns_delta = (now_wall_ns > s->window_start_wall_ns)
		? (now_wall_ns - s->window_start_wall_ns) : 0;
	enum childop_recommended_state rec = canary_recommend_state(
		op, edges, noisy_delta, wedges_delta, s->window_crashes,
		s->total_demotions);

	if (op > CHILD_OP_SYSCALL && op < NR_CHILD_OP_TYPES) {
		if (recommended_state_is_promote(rec))
			__atomic_add_fetch(
				&shm->stats.childop.would_promote[op],
				1, __ATOMIC_RELAXED);
		else if (recommended_state_is_demote(rec))
			__atomic_add_fetch(
				&shm->stats.childop.would_demote[op],
				1, __ATOMIC_RELAXED);
	}

	/* SHADOW telemetry: extended per-window summary.  wall_ns is the
	 * (close - open) delta of shm->stats.childop.wall_ns[op] for this
	 * window; producer is the child measured-syscall path that bumps
	 * the cumulative slot. */
	output(0, "canary_shadow: %s window-close clean_edges=%lu noisy_edges_seen=%lu wall_ns=%lu wedges=%lu setup_ok=%lu setup_failures=%lu crashes=%u recommended_state=%s\n",
		s->name, edges, noisy_delta, wall_ns_delta, wedges_delta,
		setup_ok_delta, setup_fail_delta, s->window_crashes,
		childop_recommended_state_name(rec));

	if (s->window_crashes >= CANARY_CRASH_THRESHOLD) {
		leave_canarying_demote(op, "crash_threshold", iters, edges,
				       noisy_delta);
		return;
	}

	if (edges >= CANARY_EDGE_THRESHOLD) {
		leave_canarying_promote(op, iters, edges);
		return;
	}

	/* Invariant: an op cannot be demoted on childop_edges_clean[]
	 * unless it is eligible to populate it.  Ops whose dispatch
	 * shape carries no outer KCOV bracket (e.g. CHILD_OP_SCHED_CYCLER;
	 * CHILD_OP_SYSCALL is already filtered upstream by the picker)
	 * have a permanently zero clean-edge slot, so the zero_edges
	 * comparison above would unconditionally false-demote them
	 * regardless of their actual usefulness.  Route them through
	 * the canary-ineligible exit instead. */
	if (!op_uses_outer_bracket(op)) {
		leave_canarying_ineligible(op, iters, edges);
		return;
	}

	{
		/* PC-trial retry gate: the window failed to accrue clean edges
		 * AND every canary-slot dispatch of this op landed in the CMP-
		 * mode reject arm of kcov_bracket_begin() (childop_edges_
		 * clean[op] could not have grown regardless of the op's actual
		 * productivity).  Re-canary instead, up to CANARY_PC_TRIAL_
		 * RETRIES_MAX times; each re-entry kills the slot children and
		 * forces a fresh kcov-mode draw at respawn, giving a subsequent
		 * window another chance to land on a PC-mode child.
		 *
		 * Per-reason deltas are what makes the "CMP-only" label sound:
		 * bracketed_delta == 0 alone conflates the CMP arm (retry can
		 * help) with the nested arm (lifecycle-invariant violation --
		 * a caller-side bug; retry cannot help) and the inactive arm
		 * (kcov attribution off run-wide; retry cannot turn it on).
		 * The invariant
		 *   attempts == bracketed + skipped_cmp + skipped_nested
		 *             + skipped_inactive
		 * means skipped_cmp_delta == attempts_delta is exactly the
		 * shape "attempts > 0 AND every reject was CMP-mode" -- the
		 * only shape a mode-redraw retry can improve.  Any other mix
		 * falls through to the standard demote path so a productive
		 * op is not demoted on a false zero-bracket signal from a
		 * window whose rejects were dominated by a caller-side or
		 * config-side confound.
		 *
		 * Guards:
		 *   attempts_delta > 0          the outer bracket was actually
		 *                               engaged this window; with 0
		 *                               attempts childop-kcov attri-
		 *                               bution is off run-wide.
		 *   skipped_cmp_delta ==        ALL rejects were CMP-mode;
		 *     attempts_delta            no nested / inactive noise.
		 *   retries < MAX               bounded so a pathological
		 *                               all-CMP config terminates. */
		unsigned long now_attempts = kcov_shm
			? __atomic_load_n(
				&kcov_shm->childop_kcov.childop_kcov_op_attempts[op],
				__ATOMIC_RELAXED)
			: 0;
		unsigned long now_skipped_cmp = kcov_shm
			? __atomic_load_n(
				&kcov_shm->childop_kcov.childop_kcov_op_skipped_cmp[op],
				__ATOMIC_RELAXED)
			: 0;
		unsigned long now_skipped_nested = kcov_shm
			? __atomic_load_n(
				&kcov_shm->childop_kcov.childop_kcov_op_skipped_nested[op],
				__ATOMIC_RELAXED)
			: 0;
		unsigned long attempts_delta =
			(now_attempts > s->window_start_kcov_op_attempts)
			? (now_attempts - s->window_start_kcov_op_attempts) : 0;
		unsigned long skipped_cmp_delta =
			(now_skipped_cmp > s->window_start_kcov_op_skipped_cmp)
			? (now_skipped_cmp - s->window_start_kcov_op_skipped_cmp) : 0;
		unsigned long skipped_nested_delta =
			(now_skipped_nested > s->window_start_kcov_op_skipped_nested)
			? (now_skipped_nested - s->window_start_kcov_op_skipped_nested) : 0;

		/* Nested-rejection breadcrumb: a nested reject means an outer
		 * bracket was already owned when the childop dispatch tried to
		 * open its own -- a lifecycle-invariant violation on the
		 * caller side (a stray bracket outlived its scope, or an inner
		 * childop nested a call that itself opens a bracket).  Retry
		 * cannot fix it; the counter (childop_kcov_op_skipped_nested
		 * [op]) already logs the raw count run-wide, so we just report
		 * the per-window observation so operators can correlate with
		 * the op that surfaced it. */
		if (skipped_nested_delta > 0) {
			output(0, "canary: %s nested-rejection observed: skipped_nested_delta=%lu attempts_delta=%lu (lifecycle-invariant violation in kcov_bracket_begin; not retry-eligible) in %lu iters\n",
				s->name, skipped_nested_delta,
				attempts_delta, iters);
		}

		if (attempts_delta > 0 && skipped_cmp_delta == attempts_delta &&
		    s->consecutive_no_pc_bracket < CANARY_PC_TRIAL_RETRIES_MAX) {
			s->consecutive_no_pc_bracket++;
			output(0, "canary: %s pre-demote PC-trial retry %u/%u: %lu bracket attempts opened 0 (kcov_mode_cmp children only; edges=%lu noisy_edges_seen=%lu in %lu iters); re-canarying to re-draw slot kcov mode\n",
				s->name, s->consecutive_no_pc_bracket,
				(unsigned int)CANARY_PC_TRIAL_RETRIES_MAX,
				attempts_delta, edges, noisy_delta, iters);
			enter_canarying(op);
			return;
		}

		/* Route the "zero clean edges" demote through the specific
		 * kcov_bracket_begin() skip reason when one applies.  Same
		 * confound the shadow's CHILDOP_REC_UNATTRIBUTED_EDGES
		 * recommendation guards against: an op that never opens a
		 * PC bracket (e.g. KCOV_MODE_CMP child) cannot possibly
		 * accrue childop_edges_clean[], so the generic "zero_edges"
		 * label mis-attributes the confound to the op itself.  The
		 * noisy_delta > 0 gate mirrors canary_recommend_state();
		 * with clean_delta == 0 && noisy_delta == 0 the window is
		 * genuinely dry and the legacy label is correct. */
		const char *demote_reason = "zero_edges";
		if (noisy_delta > 0) {
			const char *skip = op_kcov_skip_reason(op);
			if (skip != NULL)
				demote_reason = skip;
		}
		leave_canarying_demote(op, demote_reason, iters, edges,
				       noisy_delta);
	}
}

/* --------------------------------------------------------------------
 * Public entry points.
 * -------------------------------------------------------------------- */

void canary_queue_init(void)
{
	unsigned int i;
	enum child_op_type seed;
	unsigned int dormant_eligible = 0;
	unsigned int config_blocked = 0;

	memset(canary_ops, 0, sizeof(canary_ops));
	memset(canary_op_setup_broken, 0, sizeof(canary_op_setup_broken));
	for (i = 0; i < NR_CHILD_OP_TYPES; i++) {
		canary_ops[i].op = (enum child_op_type)i;
		canary_ops[i].name = alt_op_name((enum child_op_type)i);
		canary_ops[i].state = CANARY_STATE_DORMANT;
	}

	/* CONFIG_BLOCKED set: terminal, never picked.  Also stamp the
	 * static reason hint so the startup enumeration and any later
	 * canary_queue_summary() consumer can report a label instead of
	 * a bare "config-blocked" state. */
	for (i = 0; i < canary_config_blocked_count; i++) {
		enum child_op_type op = canary_config_blocked[i];
		if (op < NR_CHILD_OP_TYPES) {
			canary_ops[op].state = CANARY_STATE_CONFIG_BLOCKED;
			canary_ops[op].blocked_reason =
				CANARY_BLOCKED_REASON_CONFIG_ABSENT;
			canary_ops[op].setup_fail_reason =
				canary_setup_fail_reason_for_op(op);
		}
	}

	/* Risky-defer set: stay DORMANT but the picker skips them via
	 * the phase1_ineligible flag.  These ops need isolation that the
	 * queue does not provide. */
	for (i = 0; i < canary_risky_defer_count; i++) {
		enum child_op_type op = canary_risky_defer[i];
		if (op < NR_CHILD_OP_TYPES)
			canary_ops[op].phase1_ineligible = true;
	}

	/* Synthetic PROMOTED state for every op currently active in the
	 * dormant gate, so the queue's summary count agrees with reality
	 * at t=0.  CHILD_OP_SYSCALL is not an alt-op and is skipped. */
	for (i = (unsigned int)CHILD_OP_SYSCALL + 1; i < NR_CHILD_OP_TYPES; i++) {
		if (dormant_op_is_active((enum child_op_type)i)) {
			canary_ops[i].state = CANARY_STATE_PROMOTED;
			canary_ops[i].total_promotions = 1;
		}
	}

	/* Counters for the startup banner. */
	for (i = (unsigned int)CHILD_OP_SYSCALL + 1; i < NR_CHILD_OP_TYPES; i++) {
		switch (canary_ops[i].state) {
		case CANARY_STATE_CONFIG_BLOCKED:
			config_blocked++;
			break;
		case CANARY_STATE_DORMANT:
			if (!canary_ops[i].phase1_ineligible)
				dormant_eligible++;
			break;
		default:
			break;
		}
	}

	/* Priority list: built-in unless --canary-seed overrode it. */
	if (canary_seed_override_count > 0) {
		for (i = 0; i < canary_seed_override_count; i++)
			canary_seed_override_widened[i] =
				(enum child_op_type)canary_seed_override[i];
		canary_priority_list = canary_seed_override_widened;
		canary_priority_list_count = canary_seed_override_count;
	} else {
		canary_priority_list = canary_priority_seeds;
		canary_priority_list_count = canary_priority_seeds_count;
	}

	canary_priority_cursor = 0;
	canary_fifo_cursor = CHILD_OP_SYSCALL;
	canary_active_op_cell = CHILD_OP_SYSCALL;
	canary_pending_op = CHILD_OP_SYSCALL;
	canary_active_op_set = false;
	canary_pending_op_set = false;
	canary_slots_parked = false;
	canary_promotion_ring_count = 0;
	canary_promotion_ring_head = 0;
	canary_last_summary = monotonic_seconds();
	canary_last_plateau = false;

	/* Gate the live state on the operator flags AND on having at
	 * least one slot to canary on.  Both kill switches map to the
	 * same disabled-no-op behaviour.
	 *
	 * -c <syscall>, -r <num>, and -g <group> scope the run to a
	 * specific syscall set for isolation / bisection.  The canary
	 * queue would otherwise stage dormant alt-op childops onto its
	 * dedicated slots and execute them (entering canarying windows
	 * and promoting/demoting based on edges/crashes), bypassing the
	 * syscall-table gate exactly like the picker-leak and
	 * periodic-work paths that the child_process() / periodic_work()
	 * gates already cover.  Stay dormant so the targeted-syscall
	 * signal is not contaminated by canary-discovered edges / crashes
	 * getting mis-credited to the target syscall. */
	canary_queue_live = (!canary_queue_disabled) && (canary_slots > 0) &&
		!do_specific_syscall && !random_selection &&
		desired_group == GROUP_NONE;

	if (!canary_queue_live) {
		if (canary_queue_disabled) {
			output(0, "canary queue: disabled (--no-canary-queue); dormant_op_disabled[] used as static gate\n");
		} else if (do_specific_syscall || random_selection ||
			   desired_group != GROUP_NONE) {
			output(0, "canary queue: disabled (targeted-syscall mode -c/-r/-g); dormant_op_disabled[] used as static gate\n");
		} else {
			/* canary_slots == 0 -- either explicit
			 * --canary-slots=0 or alt_op_children=0 collapsed
			 * the auto-derived value to zero.  The boot log
			 * above this line shows which. */
			output(0, "canary queue: disabled (canary_slots=0); dormant_op_disabled[] used as static gate\n");
		}
		return;
	}

	output(0, "canary queue: enabled, slots=%u, window=%u iters, priority_seeds=%u, dormant_eligible=%u, config_blocked=%u\n",
		canary_slots, window_iters_resolved(),
		canary_priority_list_count, dormant_eligible, config_blocked);

	/* Startup CONFIG_BLOCKED table: enumerate each blocked op with the
	 * missing host-feature reason so an operator reading the boot log
	 * can tell which host features are absent without cross-
	 * referencing the hint table in source.  Emitted only in enabled
	 * mode -- the disabled bailout above already says the static gate
	 * is in use, and per-op detail is not actionable there. */
	for (i = (unsigned int)CHILD_OP_SYSCALL + 1; i < NR_CHILD_OP_TYPES; i++) {
		if (canary_ops[i].state != CANARY_STATE_CONFIG_BLOCKED)
			continue;
		output(0, "canary queue: config-blocked op %s (subreason: %s, hint: %s)\n",
			canary_ops[i].name,
			canary_blocked_reason_name(
				canary_ops[i].blocked_reason),
			canary_setup_fail_reason_name(
				canary_ops[i].setup_fail_reason));
	}

	/* Pick the first op and enter CANARYING immediately so the
	 * fleet starts working it as soon as fork_children() runs. */
	if (pick_next_canary(&seed))
		enter_canarying(seed);

	/* Silence compiler about input tables when build configs avoid
	 * the picker (none today, but keeps the warning surface clean). */
	(void)canary_priority_seeds;
	(void)canary_config_blocked;
	(void)canary_risky_defer;
}

/* retry_parked_slot(), stage_next_or_park(), close_window_or_park(),
 * log_plateau_edge() and canary_queue_tick() moved to
 * child-canary-picker.c.  canary_queue_summary() and canary_queue_on_crash()
 * moved to child-canary-report.c. */

void canary_queue_on_child_respawn(int childno)
{
	if (!canary_queue_live)
		return;
	if (canary_slots == 0 || childno < 0)
		return;
	if ((unsigned int)childno >= canary_slots)
		return;
	if (!canary_pending_op_set)
		return;

	/* Commit the staged op as the active op.  The two-stage commit
	 * means the new op only becomes the slot's running op once a
	 * child has actually been forked with it stamped -- straggler
	 * iterations of the OLD op (the previous canary, asked to die
	 * via kill_pid) do not pollute the new op's counters.
	 *
	 * The caller (spawn_child) invokes us BEFORE
	 * assign_dedicated_alt_op() so the dedicated stamp sees the
	 * just-committed active op rather than the previous canary; if
	 * we committed after the stamp, the freshly-spawned child would
	 * have the old op stamped while the queue tracked the new op.
	 *
	 * Clear canary_pending_op_set once committed so that stale
	 * pending state cannot influence later canary_active_op() reads
	 * (e.g. the picker-exhausted path in canary_queue_tick() then
	 * sees a clean slate). */
	canary_active_op_cell = canary_pending_op;
	canary_active_op_set = true;
	canary_pending_op_set = false;
}

/* canary_slot_active(), canary_active_op(), and canary_op_is_promoted()
 * moved to child-canary-report.c. */
