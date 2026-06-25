/*
 * child-canary.c -- Dormant-childop canary promotion queue.
 *
 * The queue flips the runtime gate (dormant_op_disabled[]) for one
 * dormant op at a time, runs that op on a reserved canary child for a
 * fixed iteration budget, and promotes the op into the random alt-op
 * picker when it produces new edges without self-crashing.  Failed
 * canaries are demoted with a backoff.  The slots are carved from the
 * front of the existing --alt-op-children pool.
 *
 * State lives entirely in parent-private static memory.  The gate
 * vector (dormant_op_disabled[]) and the dense enabled_altops[]
 * vector rebuilt from it are seeded into children by fork() COW, so
 * the INITIAL snapshot is shared, but they are not shm-resident: any
 * runtime flip from dormant_op_set() is parent-only.
 *
 * Propagation model: state changes here are seen by NEW children (next
 * respawn forward).  Already-running random children -- those at slot
 * index >= alt_op_children, where pick_op_type() may select an alt-op
 * with ~5% probability -- continue with their fork-time snapshot of
 * dormant_op_disabled[] / enabled_altops[] until they exit.  Slot
 * turnover (the natural respawn cadence) propagates the new state
 * organically across the fleet.  Dedicated canary slots (the first
 * canary_slots indices) re-stamp their op_type on every respawn via
 * assign_dedicated_alt_op() and so always see the current queue state.
 *
 * Runtime promotions/demotions are deliberately not published into the
 * shared region: already-forked random children would need an shm-
 * resident gate (plus persistence) to observe them, and that cost is
 * not paid here.
 *
 * No childop implementation is modified by this queue.  A broken op
 * is detected via the demote path; the cure is to leave it dormant.
 *
 * The priority seed list (consumed in this order before the FIFO walk
 * over remaining dormant ops): genetlink_fuzzer, bpf_lifecycle,
 * iouring_recipes, nftables_churn, perf_chains, tracefs_fuzzer,
 * tls_rotate, af_unix_scm_rights_gc_churn, userns_fuzzer,
 * sock_diag_walker.
 */
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
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
 * through --canary-slots / --canary-window in params.c.
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

/* Seconds a DEMOTED op must wait before re-entering the picker.  Long
 * enough that a backed-off op does not churn-cycle, short enough that
 * a single multi-hour fuzz run gets to re-test misjudged ops. */
#define CANARY_BACKOFF_TIME		1800

/* Per-window setup-failure count above which a canary op with zero
 * setup successes is treated as structurally broken (vs. low-yield)
 * and the window is aborted early.  500 = enough to filter the slow
 * start of a transient EAGAIN/ENOMEM burst, well below the full
 * 10000-iter window so a re-test costs ~500 invocations not ~10000.
 * Tied to setup_ok_delta == 0: an op with any setup success at all
 * is not "broken at setup", just bad at it. */
#define CANARY_SETUP_BROKEN_FAILS	500U

/* Backoff for an op demoted with reason setup_broken.  Much longer
 * than CANARY_BACKOFF_TIME because a 100%-setup-failure shape will
 * not self-heal in 30 minutes -- it needs a code fix to the op's
 * setup path (missing kconfig probe, stale capability check, wrong
 * netns scope).  Re-canarying before then just burns another window
 * rediscovering the same broken setup.  4 h is still inside a single
 * long fuzz session, so a fix that lands mid-run does get re-evaluated. */
#define CANARY_SETUP_BROKEN_BACKOFF_TIME	(4 * 3600)

/* Width of the small ring of recently-promoted op names rendered by
 * canary_queue_summary().  Fixed at 5; spec verbatim. */
#define CANARY_PROMOTION_RING_SIZE	5

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

/* Queue-summary cadence (60 s; spec verbatim).  Per-window-progress
 * lines are emitted from the ~1 s tick path with no extra rate-limit
 * (one line per tick while CANARYING). */
#define CANARY_SUMMARY_INTERVAL_SEC	60

/* --------------------------------------------------------------------
 * Priority seed list and skip sets.  These are the operator-visible
 * inputs to the queue's picker order.
 *
 * Priority seeds are consumed before the general FIFO walk over remaining
 * dormant ops.  config_blocked is permanent (CONFIG_BLOCKED state at
 * startup, never picked).  risky_defer is left in DORMANT but the
 * picker silently skips it -- these ops need isolation (root-only /
 * inner-fork / SR-IOV / driver prereq) that the queue does not
 * provide.
 * -------------------------------------------------------------------- */

static const enum child_op_type canary_priority_seeds[] = {
	CHILD_OP_GENETLINK_FUZZER,
	CHILD_OP_BPF_LIFECYCLE,
	CHILD_OP_IOURING_RECIPES,
	CHILD_OP_NFTABLES_CHURN,
	CHILD_OP_PERF_CHAINS,
	CHILD_OP_TRACEFS_FUZZER,
	CHILD_OP_TLS_ROTATE,
	CHILD_OP_AF_UNIX_SCM_RIGHTS_GC,
	CHILD_OP_USERNS_FUZZER,
	CHILD_OP_SOCK_DIAG_WALKER,
};
#define CANARY_PRIORITY_COUNT	ARRAY_SIZE(canary_priority_seeds)

static const enum child_op_type canary_config_blocked[] = {
	CHILD_OP_NUMA_MIGRATION,
	CHILD_OP_TIPC_LINK_CHURN,
	CHILD_OP_SCTP_ASSOC_CHURN,
	CHILD_OP_NL80211_CHURN,
	CHILD_OP_UBLK_LIFECYCLE,
	CHILD_OP_IP6ERSPAN_NETNS_MIGRATE,
	CHILD_OP_ATM_VCC_CHURN,
	CHILD_OP_IP6GRE_BOND_LAPB_STACK,
};

/* Pid-heavy ops the picker temporarily evicts while the parent fork
 * loop is in the drain window (see fork_pressure_drain_active() in
 * main.c).  Membership criteria: the op either fork()s short-lived
 * helper workers internally (and bumps a *_fork_failed counter when
 * that inner fork fails -- those five are the same set surfaced in
 * main.c's bail-time subworker fork-fail dump) or its primary purpose
 * is hammering the pid/pidfd allocator (pidfd_storm).  fork_storm
 * is double-gated: it is already in canary_risky_defer below, but is
 * listed here for completeness so a future risky-defer reshuffle
 * cannot quietly let it through the drain. */
static const enum child_op_type canary_pid_heavy_ops[] = {
	CHILD_OP_FORK_STORM,
	CHILD_OP_PIDFD_STORM,
	CHILD_OP_QRTR_BIND_RACE,
	CHILD_OP_PFKEY_SPD_WALK,
	CHILD_OP_L2TP_IFNAME_RACE,
	CHILD_OP_STATMOUNT_IDMAP_OVERFLOW,
	CHILD_OP_SYSFS_STRING_RACE,
};

static const enum child_op_type canary_risky_defer[] = {
	CHILD_OP_FORK_STORM,
	CHILD_OP_CPU_HOTPLUG_RIDER,
	CHILD_OP_VDSO_MREMAP_RACE,
	CHILD_OP_BARRIER_RACER,
	CHILD_OP_MOUNT_CHURN,
	CHILD_OP_UFFD_CHURN,
	CHILD_OP_DEVLINK_PORT_CHURN,
	CHILD_OP_RTNL_VF_BROADCAST_GETLINK,
	CHILD_OP_TTY_LDISC_CHURN,
};

/* --------------------------------------------------------------------
 * Per-op queue state.  Parent-private; indexed by child_op_type enum.
 * -------------------------------------------------------------------- */

static struct canary_op_state canary_ops[NR_CHILD_OP_TYPES];

/* Picker cursors.  canary_priority_cursor is the next index into
 * canary_priority_seeds[] (or the operator-supplied override).  fifo_cursor
 * is the last enum value picked from the general FIFO walk; the next
 * pick resumes from cursor+1 and wraps. */
static unsigned int canary_priority_cursor = 0;
static enum child_op_type canary_fifo_cursor = CHILD_OP_SYSCALL;

/* Resolved priority-seed list pointer.  Defaults to the built-in seed array;
 * if --canary-seed was passed, the parser put op enums into
 * canary_seed_override[] / canary_seed_override_count and the init path
 * swaps that in. */
static const enum child_op_type *canary_priority_list = NULL;
static unsigned int canary_priority_list_count = 0;

/* Storage backing canary_priority_list when --canary-seed is in use.  The
 * parser stuffs unsigned-char-narrowed op enums into
 * canary_seed_override[]; we widen them into a real enum array here so
 * the picker can iterate by value rather than by re-casting on every
 * pick. */
static enum child_op_type canary_seed_override_widened[CANARY_SEED_OVERRIDE_MAX];

/* Active op the canary slot(s) should be running right now.  Two-stage
 * commit: enter_canarying() writes canary_pending_op and stamps the
 * window-start counters, but canary_active_op_cell is only flipped
 * when canary_queue_on_child_respawn() fires -- the slot's previous
 * child has actually exited and a fresh one has been forked with the
 * new op.  Straggler iterations of the old op therefore do not
 * pollute the new op's window edges/crashes counters. */
static enum child_op_type canary_active_op_cell = CHILD_OP_SYSCALL;
static enum child_op_type canary_pending_op = CHILD_OP_SYSCALL;
static bool canary_active_op_set = false;
static bool canary_pending_op_set = false;

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
static bool canary_slots_parked = false;

/* True once the queue is fully initialised AND not gated off by
 * --no-canary-queue / canary_slots=0.  When false, every public entry
 * point returns immediately and the dormant gate is consulted as a
 * historical static vector. */
static bool canary_queue_live = false;

/* Recently-promoted op names, ring of last CANARY_PROMOTION_RING_SIZE
 * entries.  Rendered by the 60-s summary line when at least one
 * promotion has occurred. */
static enum child_op_type canary_promotion_ring[CANARY_PROMOTION_RING_SIZE];
static unsigned int canary_promotion_ring_count = 0;
static unsigned int canary_promotion_ring_head = 0;

/* Cached time of last summary emit; the summary self-rate-limits. */
static time_t canary_last_summary = 0;

/* Last observed plateau_active value, used for edge-triggered logging in
 * canary_queue_tick().  File-static (not a function-local static) so
 * canary_queue_init() can reset it per-epoch -- otherwise stale state from
 * the previous epoch would suppress the first plateau-change log of the
 * new epoch (or emit a spurious one if the flag flipped while the queue
 * was reinitialising). */
static bool canary_last_plateau = false;

/* Per-op latch set by leave_canarying_demote_setup_broken() to mark an op
 * whose last demotion was for 100%-setup-failure shape.  Read by the
 * picker's DEMOTED-state backoff check, which then uses
 * CANARY_SETUP_BROKEN_BACKOFF_TIME instead of CANARY_BACKOFF_TIME.
 * Cleared in enter_canarying() so a re-canary that survives (or hits a
 * different demote reason) drops back to the normal backoff schedule. */
static bool canary_op_setup_broken[NR_CHILD_OP_TYPES];

/* --------------------------------------------------------------------
 * Helpers.
 * -------------------------------------------------------------------- */

/* Wall-clock-skew-immune second counter for state-transition stamps and
 * the summary throttle.  CLOCK_MONOTONIC cannot fail on a supported
 * kernel, so the return is taken unconditionally. */
static time_t monotonic_seconds(void)
{
	struct timespec ts;
	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

static unsigned int window_iters_resolved(void)
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
	    __atomic_load_n(&kcov_shm->plateau_active, __ATOMIC_ACQUIRE))
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
static unsigned long edges_for_op(enum child_op_type op)
{
	if (op >= NR_CHILD_OP_TYPES)
		return 0UL;
	return __atomic_load_n(&shm->stats.childop_edges_clean[op],
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
static unsigned long invocations_for_op(enum child_op_type op)
{
	if (op >= NR_CHILD_OP_TYPES)
		return 0UL;
	return __atomic_load_n(&shm->stats.childop_invocations[op],
			       __ATOMIC_RELAXED);
}

/* Table-membership helper kept local to the canary picker.  The picker
 * currently uses inline state-bit checks instead, so there is no live
 * caller; keep it declared but marked unused until the picker grows a
 * second table walk. */
static bool op_is_in_table(enum child_op_type op,
			   const enum child_op_type *tbl,
			   unsigned int n) __attribute__((unused));
static bool op_is_in_table(enum child_op_type op,
			   const enum child_op_type *tbl,
			   unsigned int n)
{
	unsigned int i;
	for (i = 0; i < n; i++)
		if (tbl[i] == op)
			return true;
	return false;
}

/* Drain-mode predicate: skip pid-heavy ops in the canary picker while
 * the parent fork loop is in its post-threshold recovery window.  The
 * arming side lives in main.c (fork_children); here we just consult
 * the published deadline.  Three short-circuits keep the hot path
 * cheap on the default (--fork-pressure-drain off) run: the flag
 * check, the deadline-is-zero check, and the small-array membership
 * walk only runs once the first two say yes.
 *
 * Active CANARYING is not interrupted -- this only filters NEW picks
 * from pick_next_canary().  Letting the in-flight window close
 * naturally avoids polluting the op's window counters with a forced
 * mid-window kill, and the slot's contribution to pid pressure is
 * already bounded by the existing window-iter budget. */
static bool fork_pressure_should_suppress(enum child_op_type op)
{
	unsigned long until;
	struct timespec ts;
	unsigned int i;

	if (!fork_pressure_drain)
		return false;
	until = fork_pressure_drain_active();
	if (until == 0)
		return false;
	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	if ((unsigned long)ts.tv_sec >= until)
		return false;

	for (i = 0; i < ARRAY_SIZE(canary_pid_heavy_ops); i++)
		if (canary_pid_heavy_ops[i] == op)
			return true;
	return false;
}

static void push_promotion(enum child_op_type op)
{
	canary_promotion_ring[canary_promotion_ring_head] = op;
	canary_promotion_ring_head =
		(canary_promotion_ring_head + 1) % CANARY_PROMOTION_RING_SIZE;
	if (canary_promotion_ring_count < CANARY_PROMOTION_RING_SIZE)
		canary_promotion_ring_count++;
}

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

static void kill_canary_slot_children(void)
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

static void enter_canarying(enum child_op_type op)
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
			&shm->stats.childop_edges_discovered[op],
			__ATOMIC_RELAXED);
		unsigned long clean = __atomic_load_n(
			&shm->stats.childop_edges_clean[op],
			__ATOMIC_RELAXED);
		unsigned long setup_accepted = __atomic_load_n(
			&shm->stats.childop_setup_accepted[op],
			__ATOMIC_RELAXED);
		unsigned long invocations_now = __atomic_load_n(
			&shm->stats.childop_invocations[op],
			__ATOMIC_RELAXED);

		s->window_start_noisy_edges = (discovered > clean)
			? (discovered - clean) : 0;
		s->window_start_wedges = __atomic_load_n(
			&shm->stats.childop_wedge_count[op],
			__ATOMIC_RELAXED);
		s->window_start_setup_accepted = setup_accepted;
		s->window_start_setup_failures = (invocations_now > setup_accepted)
			? (invocations_now - setup_accepted) : 0;
		s->window_start_wall_ns = __atomic_load_n(
			&shm->stats.childop_wall_ns[op],
			__ATOMIC_RELAXED);
	}

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
}

static void leave_canarying_demote(enum child_op_type op,
				   const char *reason,
				   unsigned long window_iters,
				   unsigned long window_edges)
{
	struct canary_op_state *s = &canary_ops[op];

	s->state = CANARY_STATE_DEMOTED;
	s->last_state_transition = monotonic_seconds();
	s->total_demotions++;

	/* Flip the gate back to dormant so the random picker stops
	 * including this op. */
	dormant_op_set(op, true);

	output(0, "canary: %s demoted (reason: %s; edges=%lu crashes=%u in %lu iters; backoff=%us; effective for new children at next respawn)\n",
		s->name, reason, window_edges, s->window_crashes,
		window_iters, (unsigned int)CANARY_BACKOFF_TIME);
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
static void leave_canarying_demote_setup_broken(enum child_op_type op,
						unsigned long window_iters,
						unsigned long setup_failures)
{
	struct canary_op_state *s = &canary_ops[op];

	s->state = CANARY_STATE_DEMOTED;
	s->last_state_transition = monotonic_seconds();
	s->total_demotions++;
	canary_op_setup_broken[op] = true;

	/* Flip the gate back to dormant so the random picker stops
	 * including this op. */
	dormant_op_set(op, true);

	/* Loud log: operator-facing call to action, distinct from the
	 * routine "demoted (reason: zero_edges ...)" line so a grep for
	 * BROKEN-SETUP surfaces only the structural-failure cases. */
	output(0, "canary: %s BROKEN-SETUP: 100%% setup failure (setup_failures=%lu, setup_ok=0 in %lu iters) -- fix this op; backoff=%us before re-test; effective for new children at next respawn\n",
		s->name, setup_failures, window_iters,
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
	s->last_state_transition = monotonic_seconds();

	dormant_op_set(op, true);

	output(0, "canary: %s canary-ineligible (reason: no outer bracket; edges=%lu crashes=%u in %lu iters; terminal, no backoff retry; effective for new children at next respawn)\n",
		s->name, window_edges, s->window_crashes, window_iters);
}

/* --------------------------------------------------------------------
 * Picker.
 * -------------------------------------------------------------------- */

static bool pick_next_canary(enum child_op_type *out)
{
	unsigned int safety;
	enum child_op_type op;
	time_t now;

	/* Seed-priority queue: priority seeds first.  fork-pressure drain
	 * is consulted here so a pid-heavy seed defers to the next seed
	 * during the recovery window instead of being skipped permanently:
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

/* --------------------------------------------------------------------
 * Shadow recommendation: telemetry-only score-driven verdict on the
 * just-closed canary window.  Computed alongside the live decision
 * below; never replaces it.  Bumps shm->stats.childop_would_demote /
 * childop_would_promote and emits one canary_shadow log line so the
 * operator (and the 75.2.B enforcement work) can see how often the
 * score-driven verdict would diverge from the live one before the
 * picker is rewired.
 *
 * Recommendation precedence:
 *   CONFIG_BLOCKED   dispatch shape has no outer KCOV bracket.
 *   QUARANTINED      crash threshold tripped AND the op has been
 *                    demoted at least once already (repeated bad
 *                    windows; matches the codex QUARANTINED criterion).
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
		return CHILDOP_REC_CONFIG_BLOCKED;
	if (window_crashes >= CANARY_CRASH_THRESHOLD) {
		if (prior_demotions > 0)
			return CHILDOP_REC_QUARANTINED;
		return CHILDOP_REC_THROTTLED;
	}
	if (clean_edges_delta >= CANARY_EDGE_THRESHOLD)
		return CHILDOP_REC_PROMOTED_CLEAN;
	if (clean_edges_delta == 0 && noisy_edges_delta > 0)
		return CHILDOP_REC_PROMOTED_INTERFERENCE;
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
	case CHILDOP_REC_CONFIG_BLOCKED:	return "CONFIG_BLOCKED";
	}
	return "UNKNOWN";
}

static bool recommended_state_is_promote(enum childop_recommended_state s)
{
	return s == CHILDOP_REC_PROMOTED_CLEAN ||
	       s == CHILDOP_REC_PROMOTED_INTERFERENCE;
}

static bool recommended_state_is_demote(enum childop_recommended_state s)
{
	return s == CHILDOP_REC_THROTTLED ||
	       s == CHILDOP_REC_QUARANTINED ||
	       s == CHILDOP_REC_CONFIG_BLOCKED;
}

/* --------------------------------------------------------------------
 * Window close: called from the tick once enough iterations have
 * elapsed against the active canary op.
 * -------------------------------------------------------------------- */

static void close_window_and_decide(enum child_op_type op)
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
		&shm->stats.childop_edges_discovered[op], __ATOMIC_RELAXED);
	unsigned long now_clean = now_edges;
	unsigned long now_noisy = (now_discovered > now_clean)
		? (now_discovered - now_clean) : 0;
	unsigned long noisy_delta = (now_noisy > s->window_start_noisy_edges)
		? (now_noisy - s->window_start_noisy_edges) : 0;
	unsigned long now_wedges = __atomic_load_n(
		&shm->stats.childop_wedge_count[op], __ATOMIC_RELAXED);
	unsigned long wedges_delta = (now_wedges > s->window_start_wedges)
		? (now_wedges - s->window_start_wedges) : 0;
	unsigned long now_setup_accepted = __atomic_load_n(
		&shm->stats.childop_setup_accepted[op], __ATOMIC_RELAXED);
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
		&shm->stats.childop_wall_ns[op], __ATOMIC_RELAXED);
	unsigned long wall_ns_delta = (now_wall_ns > s->window_start_wall_ns)
		? (now_wall_ns - s->window_start_wall_ns) : 0;
	enum childop_recommended_state rec = canary_recommend_state(
		op, edges, noisy_delta, wedges_delta, s->window_crashes,
		s->total_demotions);

	if (op > CHILD_OP_SYSCALL && op < NR_CHILD_OP_TYPES) {
		if (recommended_state_is_promote(rec))
			__atomic_add_fetch(
				&shm->stats.childop_would_promote[op],
				1, __ATOMIC_RELAXED);
		else if (recommended_state_is_demote(rec))
			__atomic_add_fetch(
				&shm->stats.childop_would_demote[op],
				1, __ATOMIC_RELAXED);
	}

	/* SHADOW telemetry: extended per-window summary.  wall_ns is the
	 * (close - open) delta of shm->stats.childop_wall_ns[op] for this
	 * window; producer is the child measured-syscall path that bumps
	 * the cumulative slot. */
	output(0, "canary_shadow: %s window-close clean_edges=%lu noisy_edges_seen=%lu wall_ns=%lu wedges=%lu setup_ok=%lu setup_failures=%lu crashes=%u recommended_state=%s\n",
		s->name, edges, noisy_delta, wall_ns_delta, wedges_delta,
		setup_ok_delta, setup_fail_delta, s->window_crashes,
		childop_recommended_state_name(rec));

	if (s->window_crashes >= CANARY_CRASH_THRESHOLD) {
		leave_canarying_demote(op, "crash_threshold", iters, edges);
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

	leave_canarying_demote(op, "zero_edges", iters, edges);
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

	/* CONFIG_BLOCKED set: terminal, never picked. */
	for (i = 0; i < ARRAY_SIZE(canary_config_blocked); i++) {
		enum child_op_type op = canary_config_blocked[i];
		if (op < NR_CHILD_OP_TYPES)
			canary_ops[op].state = CANARY_STATE_CONFIG_BLOCKED;
	}

	/* Risky-defer set: stay DORMANT but the picker skips them via
	 * the phase1_ineligible flag.  These ops need isolation that the
	 * queue does not provide. */
	for (i = 0; i < ARRAY_SIZE(canary_risky_defer); i++) {
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
		canary_priority_list_count = (unsigned int)CANARY_PRIORITY_COUNT;
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
	stage_next_or_park();
}

/* Edge-triggered visibility for the plateau-driven window shrink.
 * Log on both rising and falling edges so the operator can see the
 * effective budget change in real time. */
static void log_plateau_edge(void)
{
	bool now_plateau = (kcov_shm != NULL &&
		__atomic_load_n(&kcov_shm->plateau_active,
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
			&shm->stats.childop_setup_accepted[op], __ATOMIC_RELAXED);
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

	if (iters >= (unsigned long)budget)
		close_window_or_park(op);
}

void canary_queue_summary(void)
{
	unsigned int dormant = 0, canarying = 0, promoted = 0;
	unsigned int demoted = 0, blocked = 0;
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
		case CANARY_STATE_CONFIG_BLOCKED:	blocked++; break;
		}
	}

	output(0, "canary queue: %u dormant, %u canarying, %u promoted, %u demoted, %u config-blocked (total=%u)\n",
		dormant, canarying, promoted, demoted, blocked, total);

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
