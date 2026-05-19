/*
 * child-canary.c -- Dormant-childop canary promotion queue.
 *
 * Phase 1: introduces the queue, the state machine, the slot-carve from
 * the front of the existing --alt-op-children pool, and the operator-
 * visibility surface.  The queue's job is to flip the runtime gate
 * (dormant_op_disabled[]) for one dormant op at a time, run that op on
 * a reserved canary child for a fixed iteration budget, and promote
 * the op into the random alt-op picker when it produces new edges
 * without self-crashing.  Failed canaries are demoted with a backoff.
 *
 * State lives entirely in parent-private static memory.  The only
 * cross-process hand-off is the gate vector (dormant_op_disabled[])
 * and the enabled_altops[] dense vector built from it; both are
 * already process-shared by virtue of living in the parent's memory
 * the children fork off, so no new shm allocation is required.
 *
 * No childop implementation is modified by this queue.  A broken op
 * is detected via the demote path; the cure is to leave it dormant.
 *
 * Phase 1 wave-1 seed list (consumed in this order before the FIFO
 * walk over remaining dormant ops): genetlink_fuzzer, bpf_lifecycle,
 * iouring_recipes, nftables_churn, perf_chains, tracefs_fuzzer,
 * tls_rotate, af_unix_scm_rights_gc_churn, userns_fuzzer,
 * sock_diag_walker.
 */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "child.h"
#include "params.h"
#include "pids.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "trinity.h"
#include "utils.h"

/* --------------------------------------------------------------------
 * Concrete thresholds.  Tuned in the design doc; kept as #defines
 * rather than CLI flags so the operator-facing surface stays small.
 * The two operator-tunable knobs (slot count, window iters) come in
 * through --canary-slots / --canary-window in params.c.
 * -------------------------------------------------------------------- */

/* Lower / upper clamps on --canary-window; the parser enforces both,
 * but we keep the constants here so a code-side read of the bound is
 * always in agreement with the CLI. */
#define CANARY_WINDOW_ITERS_MIN		1000U
#define CANARY_WINDOW_ITERS_MAX		1000000U

/* New edges per window required to call a canary "productive".  See
 * the design doc for the calibration argument; in short, this is
 * tight enough to filter sibling-mediated KCOV noise and loose enough
 * to admit any op that actually exercises a non-trivial code path. */
#define CANARY_EDGE_THRESHOLD		50UL

/* SIGSEGV/SIGBUS/SIGILL/SIGABRT per window before we treat the op as
 * the cause of the crash and demote it.  1 is plausibly noise; 2 in
 * a 10k-iter window is a real correlation. */
#define CANARY_CRASH_THRESHOLD		2U

/* Consecutive zero-edge windows before a soft-fail demote.  Catches
 * ops that complete cleanly but never reach productive code (missing
 * NL family, absent FUSE arms, etc.). */
#define CANARY_ZERO_WINDOW_THRESHOLD	3U

/* Seconds a DEMOTED op must wait before re-entering the picker.  Long
 * enough that a backed-off op does not churn-cycle, short enough that
 * a single multi-hour fuzz run gets to re-test misjudged ops. */
#define CANARY_BACKOFF_TIME		1800

/* Width of the small ring of recently-promoted op names rendered by
 * canary_queue_summary().  Fixed at 5; spec verbatim. */
#define CANARY_PROMOTION_RING_SIZE	5

/* Queue-summary cadence (60 s; spec verbatim).  Per-window-progress
 * lines are emitted from the ~1 s tick path with no extra rate-limit
 * (one line per tick while CANARYING). */
#define CANARY_SUMMARY_INTERVAL_SEC	60

/* --------------------------------------------------------------------
 * Wave-1 seed list and audit-derived skip sets.  See the design doc;
 * these are the operator-visible inputs to the queue's picker order.
 *
 * Wave-1 is consumed before the general FIFO walk over remaining
 * dormant ops.  config_blocked is permanent (CONFIG_BLOCKED state at
 * startup, never picked).  risky_defer is left in DORMANT but the
 * picker silently skips it -- the audit flagged these ops as needing
 * isolation (root-only / inner-fork / SR-IOV / driver prereq) that
 * Phase 1 does not provide.
 * -------------------------------------------------------------------- */

static const enum child_op_type canary_wave1_seeds[] = {
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
#define CANARY_WAVE1_COUNT	ARRAY_SIZE(canary_wave1_seeds)

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

/* Picker cursors.  wave1_cursor is the next index into
 * canary_wave1_seeds[] (or the operator-supplied override).  fifo_cursor
 * is the last enum value picked from the general FIFO walk; the next
 * pick resumes from cursor+1 and wraps. */
static unsigned int canary_wave1_cursor = 0;
static enum child_op_type canary_fifo_cursor = CHILD_OP_SYSCALL;

/* Resolved wave-1 list pointer.  Defaults to the built-in seed array;
 * if --canary-seed was passed, the parser put op enums into
 * canary_seed_override[] / canary_seed_override_count and the init path
 * swaps that in. */
static const enum child_op_type *canary_wave1_list = NULL;
static unsigned int canary_wave1_list_count = 0;

/* Storage backing canary_wave1_list when --canary-seed is in use.  The
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

/* --------------------------------------------------------------------
 * Helpers.
 * -------------------------------------------------------------------- */

static unsigned int window_iters_resolved(void)
{
	unsigned int w = canary_window_iters;
	if (w < CANARY_WINDOW_ITERS_MIN)
		w = CANARY_WINDOW_ITERS_MIN;
	if (w > CANARY_WINDOW_ITERS_MAX)
		w = CANARY_WINDOW_ITERS_MAX;
	return w;
}

static unsigned long edges_for_op(enum child_op_type op)
{
	if (op >= NR_CHILD_OP_TYPES)
		return 0UL;
	return __atomic_load_n(&shm->stats.childop_edges_discovered[op],
			       __ATOMIC_RELAXED);
}

static unsigned long fleet_op_count(void)
{
	/* The parent maintains parent_stats.op_count by draining the
	 * per-child stats rings.  Reading it directly here is safe: the
	 * queue runs in parent context, the same context that updates
	 * the aggregate. */
	return parent_stats.op_count;
}

/* op_is_in_table() is reserved for an upcoming Phase 2 audit-skip
 * helper.  Phase 1's picker uses inline state-bit checks instead;
 * keep the helper declared but marked unused so adding a new caller
 * in Phase 2 stays a single-LOC change. */
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

static void kill_canary_slot_children(void)
{
	unsigned int i;

	for (i = 0; i < canary_slots && i < max_children; i++) {
		pid_t pid = __atomic_load_n(&pids[i], __ATOMIC_ACQUIRE);
		if (pid != EMPTY_PIDSLOT && pid > 0)
			kill_pid(pid);
	}
}

static void enter_canarying(enum child_op_type op)
{
	struct canary_op_state *s;
	time_t now = time(NULL);

	if (op == CHILD_OP_SYSCALL || op >= NR_CHILD_OP_TYPES)
		return;

	s = &canary_ops[op];
	s->state = CANARY_STATE_CANARYING;
	s->window_crashes = 0;
	s->window_start_op_count = fleet_op_count();
	s->window_start_edges = edges_for_op(op);
	s->last_canary_window_start = now;
	s->last_state_transition = now;
	s->canary_iterations++;

	/* Flip the gate so the random alt-op picker (and the dedicated-
	 * canary-slot stamping path) starts including this op. */
	dormant_op_set(op, false);

	/* Stage the new op as the pending canary; the next respawn of a
	 * canary slot commits it as the active op.  Force a respawn now
	 * by killing any current canary-slot child so the new op picks up
	 * quickly. */
	canary_pending_op = op;
	canary_pending_op_set = true;
	kill_canary_slot_children();
}

static void leave_canarying_promote(enum child_op_type op,
				    unsigned long window_iters,
				    unsigned long window_edges)
{
	struct canary_op_state *s = &canary_ops[op];

	s->state = CANARY_STATE_PROMOTED;
	s->last_state_transition = time(NULL);
	s->total_promotions++;
	push_promotion(op);

	/* Gate stays at 0 (active).  The random picker keeps the op. */
	dormant_op_set(op, false);

	output(1, "canary: %s promoted (window edges=%lu crashes=%u in %lu iters)\n",
		s->name, window_edges, s->window_crashes, window_iters);
}

static void leave_canarying_demote(enum child_op_type op,
				   const char *reason,
				   unsigned long window_iters,
				   unsigned long window_edges)
{
	struct canary_op_state *s = &canary_ops[op];

	s->state = CANARY_STATE_DEMOTED;
	s->last_state_transition = time(NULL);
	s->total_demotions++;

	/* Flip the gate back to dormant so the random picker stops
	 * including this op. */
	dormant_op_set(op, true);

	output(1, "canary: %s demoted (reason: %s; edges=%lu crashes=%u in %lu iters; backoff=%us)\n",
		s->name, reason, window_edges, s->window_crashes,
		window_iters, (unsigned int)CANARY_BACKOFF_TIME);
}

/* --------------------------------------------------------------------
 * Picker.
 * -------------------------------------------------------------------- */

static bool pick_next_canary(enum child_op_type *out)
{
	unsigned int safety;
	enum child_op_type op;
	time_t now;

	/* Phase 1, tier 1: wave-1 seeds first. */
	while (canary_wave1_cursor < canary_wave1_list_count) {
		op = canary_wave1_list[canary_wave1_cursor++];
		if (op == CHILD_OP_SYSCALL || op >= NR_CHILD_OP_TYPES)
			continue;
		if (canary_ops[op].state == CANARY_STATE_CONFIG_BLOCKED)
			continue;
		if (canary_ops[op].phase1_ineligible)
			continue;
		if (canary_ops[op].state == CANARY_STATE_PROMOTED)
			continue;
		*out = op;
		return true;
	}

	/* Phase 1, tier 2: FIFO over the general dormant pool.  Walks
	 * the enum in numerical order from fifo_cursor+1, wrapping.
	 * Skips CONFIG_BLOCKED, risky-defer, wave-1 (already consumed
	 * or skipped above), PROMOTED, and DEMOTED entries still inside
	 * their backoff window.  A DEMOTED whose backoff has elapsed
	 * transitions back to DORMANT here and is then eligible. */
	now = time(NULL);
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
			if (now - canary_ops[op].last_state_transition <
			    CANARY_BACKOFF_TIME)
				continue;
			/* Backoff elapsed -- promote back to DORMANT
			 * and re-enter the picker pool.  Log the
			 * transition for operator visibility. */
			canary_ops[op].state = CANARY_STATE_DORMANT;
			canary_ops[op].last_state_transition = now;
			canary_ops[op].consecutive_zero_edge_windows = 0;
			output(1, "canary: %s backoff complete, re-queued for canary\n",
				canary_ops[op].name);
		}
		/* Skip wave-1 in the FIFO walk only if it's already been
		 * canaried at least once (queue handled it already); a
		 * wave-1 seed that demoted-then-recovered should be
		 * eligible again via the same backoff path as any other
		 * op. */
		if (canary_ops[op].state == CANARY_STATE_DORMANT) {
			*out = op;
			return true;
		}
	}
	return false;
}

/* --------------------------------------------------------------------
 * Window close: called from the tick once enough iterations have
 * elapsed against the active canary op.
 * -------------------------------------------------------------------- */

static void close_window_and_decide(enum child_op_type op)
{
	struct canary_op_state *s = &canary_ops[op];
	unsigned long now_fleet = fleet_op_count();
	unsigned long now_edges = edges_for_op(op);
	unsigned long iters = (now_fleet >= s->window_start_op_count)
		? (now_fleet - s->window_start_op_count) : 0;
	unsigned long edges = (now_edges >= s->window_start_edges)
		? (now_edges - s->window_start_edges) : 0;

	if (s->window_crashes > CANARY_CRASH_THRESHOLD) {
		leave_canarying_demote(op, "crash_threshold", iters, edges);
		return;
	}

	if (edges >= CANARY_EDGE_THRESHOLD) {
		s->consecutive_zero_edge_windows = 0;
		leave_canarying_promote(op, iters, edges);
		return;
	}

	s->consecutive_zero_edge_windows++;
	if (s->consecutive_zero_edge_windows >= CANARY_ZERO_WINDOW_THRESHOLD) {
		leave_canarying_demote(op, "zero_edges_streak", iters, edges);
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
	 * the phase1_ineligible flag.  The audit flagged these as
	 * needing isolation that Phase 1 does not provide. */
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

	/* Wave-1 list: built-in unless --canary-seed overrode it. */
	if (canary_seed_override_count > 0) {
		for (i = 0; i < canary_seed_override_count; i++)
			canary_seed_override_widened[i] =
				(enum child_op_type)canary_seed_override[i];
		canary_wave1_list = canary_seed_override_widened;
		canary_wave1_list_count = canary_seed_override_count;
	} else {
		canary_wave1_list = canary_wave1_seeds;
		canary_wave1_list_count = (unsigned int)CANARY_WAVE1_COUNT;
	}

	canary_wave1_cursor = 0;
	canary_fifo_cursor = CHILD_OP_SYSCALL;
	canary_active_op_cell = CHILD_OP_SYSCALL;
	canary_pending_op = CHILD_OP_SYSCALL;
	canary_active_op_set = false;
	canary_pending_op_set = false;
	canary_promotion_ring_count = 0;
	canary_promotion_ring_head = 0;
	canary_last_summary = time(NULL);

	/* Gate the live state on the operator flags AND on having at
	 * least one slot to canary on.  Both kill switches map to the
	 * same disabled-no-op behaviour. */
	canary_queue_live = (!canary_queue_disabled) && (canary_slots > 0);

	if (!canary_queue_live) {
		output(1, "canary queue: disabled (--no-canary-queue); dormant_op_disabled[] used as static gate\n");
		return;
	}

	output(1, "canary queue: enabled, slots=%u, window=%u iters, wave1_seeds=%u, dormant_eligible=%u, config_blocked=%u\n",
		canary_slots, window_iters_resolved(),
		canary_wave1_list_count, dormant_eligible, config_blocked);

	/* Pick the first op and enter CANARYING immediately so the
	 * fleet starts working it as soon as fork_children() runs. */
	if (pick_next_canary(&seed))
		enter_canarying(seed);

	/* Silence compiler about input tables when build configs avoid
	 * the picker (none today, but keeps the warning surface clean). */
	(void)canary_wave1_seeds;
	(void)canary_config_blocked;
	(void)canary_risky_defer;
}

void canary_queue_tick(void)
{
	enum child_op_type op;
	unsigned long iters;
	unsigned long now_fleet;
	unsigned long now_edges;
	unsigned int budget;

	if (!canary_queue_live)
		return;
	if (!canary_active_op_set)
		return;

	op = canary_active_op_cell;
	if (op >= NR_CHILD_OP_TYPES)
		return;
	if (canary_ops[op].state != CANARY_STATE_CANARYING)
		return;

	now_fleet = fleet_op_count();
	now_edges = edges_for_op(op);
	iters = (now_fleet >= canary_ops[op].window_start_op_count)
		? (now_fleet - canary_ops[op].window_start_op_count) : 0;
	budget = window_iters_resolved();

	/* Per-window progress line, once per tick while CANARYING. */
	{
		unsigned long edges = (now_edges >= canary_ops[op].window_start_edges)
			? (now_edges - canary_ops[op].window_start_edges) : 0;
		output(2, "canary: %s in window %lu/%u iters (edges=%lu crashes=%u)\n",
			canary_ops[op].name, iters, budget,
			edges, canary_ops[op].window_crashes);
	}

	if (iters >= (unsigned long)budget) {
		enum child_op_type next;
		close_window_and_decide(op);
		if (pick_next_canary(&next)) {
			enter_canarying(next);
		} else {
			/* Picker exhausted: leave the slot empty until
			 * a DEMOTED op's backoff elapses.  The next
			 * tick re-tries the FIFO walk. */
			canary_pending_op_set = false;
			canary_active_op_set = false;
		}
	}
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

	now = time(NULL);
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

	output(1, "canary queue: %u dormant, %u canarying, %u promoted, %u demoted, %u config-blocked (total=%u)\n",
		dormant, canarying, promoted, demoted, blocked, total);

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
		output(1, "canary queue: last %u promotions: %s\n",
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
	 * via kill_pid) do not pollute the new op's counters. */
	canary_active_op_cell = canary_pending_op;
	canary_active_op_set = true;
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
	 * the source of truth. */
	return canary_active_op_set || canary_pending_op_set;
}

enum child_op_type canary_active_op(void)
{
	if (canary_active_op_set)
		return canary_active_op_cell;
	if (canary_pending_op_set)
		return canary_pending_op;
	return CHILD_OP_SYSCALL;
}
