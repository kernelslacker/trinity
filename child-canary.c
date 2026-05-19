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
 * This file is the home of the queue.  It is compiled into the binary
 * unconditionally and starts up disabled-by-default until commit 3
 * wires it into the dispatch path.
 */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "child.h"
#include "params.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

/* --------------------------------------------------------------------
 * Concrete thresholds.  Tuned in the design doc; kept as #defines
 * rather than CLI flags so the operator-facing surface stays small.
 * The two operator-tunable knobs (slot count, window iters) come in
 * through --canary-slots / --canary-window in params.c.
 * -------------------------------------------------------------------- */

/* Default window length when --canary-window is not passed.  Matches
 * the operator default in params.c so a code-side read of the constant
 * is always in agreement with the CLI default. */
#define CANARY_WINDOW_ITERS_DEFAULT	10000U

/* Lower / upper clamps on --canary-window: anything below the lower
 * is noise (a single multi-stage op does not get to complete enough
 * cycles), anything above the upper defeats the queue's purpose
 * (a useless op squats a slot for minutes). */
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

/* --------------------------------------------------------------------
 * Wave-1 seed list and audit-derived skip sets.  See the design doc;
 * these are the operator-visible inputs to the queue's picker order.
 *
 * Wave-1 is consumed before the general FIFO walk over remaining
 * dormant ops.  config_blocked is permanent (CONFIG_BLOCKED state at
 * startup, never picked).  risky_defer is left in DORMANT but the
 * picker silently skips it -- the audit flagged these ops as needing
 * isolation (root-only / inner-fork / SR-IOV / driver prereq) that
 * Phase 1 does not provide.\n * -------------------------------------------------------------------- */

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

/* Active op the canary slot(s) should be running right now.  Updated
 * by the queue's enter_canarying() transition; read by the dedicated-
 * alt-op stamping path (canary_active_op()) at child spawn time.
 *
 * canary_active_op_set is false before the first pick lands (queue is
 * up but no op is canarying yet) and after the queue has exhausted
 * the candidate pool with all DEMOTED entries still inside their
 * backoff window. */
static enum child_op_type canary_active_op_cell = CHILD_OP_SYSCALL;
static bool canary_active_op_set = false;

/* True once the queue is fully initialised AND active.  Phase 1
 * commit 1 leaves this false everywhere -- the queue is scaffolded
 * but no transitions fire and no slots are reserved.  Commit 3 flips
 * the gate inside canary_queue_init() based on --no-canary-queue and
 * canary_slots. */
static bool canary_queue_live = false;

/* --------------------------------------------------------------------
 * Public entry points.  Scaffolded as no-ops in commit 1 so the
 * surrounding code can be wired up in commit 3 without behaviour
 * changes in between.
 * -------------------------------------------------------------------- */

void canary_queue_init(void)
{
	unsigned int i;

	/* Zero the table defensively so a future re-init (epoch reset)
	 * lands on a clean slate.  Phase 1 has no re-init path, but
	 * the cost is trivial. */
	memset(canary_ops, 0, sizeof(canary_ops));
	for (i = 0; i < NR_CHILD_OP_TYPES; i++) {
		canary_ops[i].op = (enum child_op_type)i;
		canary_ops[i].name = alt_op_name((enum child_op_type)i);
		canary_ops[i].state = CANARY_STATE_DORMANT;
	}

	canary_active_op_cell = CHILD_OP_SYSCALL;
	canary_active_op_set = false;
	canary_queue_live = false;

	/* Silence unused-static warnings on the input tables while the
	 * queue is still scaffolded.  Commit 3 consumes them. */
	(void)canary_wave1_seeds;
	(void)canary_config_blocked;
	(void)canary_risky_defer;
}

void canary_queue_tick(void)
{
	if (!canary_queue_live)
		return;
	/* Commit 3 implements the per-tick picker / window-close logic. */
}

void canary_queue_summary(void)
{
	if (!canary_queue_live)
		return;
	/* Commit 4 emits the 60-s queue summary line. */
}

void canary_queue_on_crash(int childno, int signo)
{
	(void)childno;
	(void)signo;
	if (!canary_queue_live)
		return;
	/* Commit 3 attributes crashes to the active canary op. */
}

void canary_queue_on_child_respawn(int childno)
{
	(void)childno;
	if (!canary_queue_live)
		return;
	/* Commit 3 commits the staged canary_active_op once the slot
	 * has actually been respawned with the new op. */
}

bool canary_slot_active(int childno)
{
	if (!canary_queue_live)
		return false;
	if (canary_slots == 0 || childno < 0)
		return false;
	if ((unsigned int)childno >= canary_slots)
		return false;
	return canary_active_op_set;
}

enum child_op_type canary_active_op(void)
{
	return canary_active_op_cell;
}
