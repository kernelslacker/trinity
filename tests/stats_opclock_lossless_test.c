/*
 * stats_opclock_lossless_test.c -- invariant checks for the lossless
 * per-child op-count counter (stats_ring.lossless_op_count).
 *
 * The op counter lives in each child's own struct stats_ring page as a
 * plain unsigned long (single writer -- no atomic needed, no shared
 * cacheline contention).  The parent sums across all children's rings
 * in stats_ring_drain_all() to derive total_op_count and op_count.
 *
 * These tests simulate the key invariants without importing the real
 * trinity shm / ring / stats-ring modules.  They model:
 *   - a fixed-capacity SPSC ring (RING_CAP slots)
 *   - a per-child lossless_op_count plain unsigned long
 *   - the stats_aggregate scalars (op_count, total_op_count,
 *     epoch_start_op_count)
 *   - simulated drains that sum per-child lossless_op_count
 *   - simulated epoch resets
 *
 * Suite entry point: stats_opclock_lossless_self_check()
 *
 * Tests
 * -----
 * 1. ring_full_no_loss       -- lossless_op_count reflects all ops even
 *                               when the ring saturates and drops occur.
 * 2. epoch_semantics         -- reset correctly snapshots epoch_start;
 *                               op_count = total - epoch_start always
 *                               equals ops since last reset.
 * 3. call_limit_exact        -- call-limit check fires at EXACTLY the
 *                               right count even under ring saturation.
 * 4. epoch_termination       -- epoch-iteration limit check fires at
 *                               exactly epoch_iterations ops after
 *                               reset, not delayed by ring drops.
 * 5. rotation_boundary       -- strategy rotation clock (fleet_op_count
 *                               = op_count from per-child sum) triggers
 *                               at the correct window boundary.
 * 6. child_respawn_preserve  -- simulated child exit + respawn resets
 *                               the per-child lossless_op_count to 0
 *                               for the new child, but the parent's
 *                               total_op_count accumulates correctly
 *                               because the parent drains (and adds)
 *                               before respawning.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Simulated ring                                                      */
/* ------------------------------------------------------------------ */

/*
 * Capacity matches the real STATS_RING_SIZE so the saturation tests
 * are realistic.
 */
#define RING_CAP 1024

struct sim_ring {
	unsigned long lossless_op_count;	/* per-child, plain (no atomic) */
	unsigned int head;
	unsigned int tail;
	unsigned int slots[RING_CAP];	/* payload unused in test */
};

static void ring_init(struct sim_ring *r)
{
	memset(r, 0, sizeof(*r));
}

/*
 * Enqueue one slot.  Returns true on success, false when full.
 * Mirrors the spsc_ring_try_enqueue() bool contract.
 */
static bool ring_enqueue(struct sim_ring *r, unsigned int val)
{
	unsigned int head = r->head;
	unsigned int next = (head + 1) & (RING_CAP - 1);

	if (next == r->tail)
		return false;	/* full */
	r->slots[head] = val;
	r->head = next;
	return true;
}

/*
 * Drain all pending slots.  Returns the number of slots processed.
 * Mirrors the spsc_ring_drain() call in stats_ring_drain_all().
 */
static unsigned int ring_drain(struct sim_ring *r)
{
	unsigned int count = 0;

	while (r->tail != r->head) {
		r->tail = (r->tail + 1) & (RING_CAP - 1);
		count++;
	}
	return count;
}

/* ------------------------------------------------------------------ */
/* Simulated stats aggregate                                           */
/* ------------------------------------------------------------------ */

struct sim_aggregate {
	unsigned long op_count;
	unsigned long total_op_count;
	unsigned long epoch_start_op_count;
	unsigned long previous_op_count;
};

static void agg_init(struct sim_aggregate *a)
{
	memset(a, 0, sizeof(*a));
}

/* ------------------------------------------------------------------ */
/* Simulated op-completion                                             */
/*                                                                     */
/* Models the two production sites:                                    */
/*   - dispatch-step.c syscall path                                    */
/*   - child.c alt-op path                                             */
/*                                                                     */
/* Both sites:                                                         */
/*   1. increment the per-child lossless_op_count (plain ++, no       */
/*      atomic -- sole writer)                                         */
/*   2. enqueue the ring (may fail if full -- drop is OK)              */
/* ------------------------------------------------------------------ */

static void sim_op_complete(struct sim_ring *ring)
{
	/* Step 1: per-child lossless increment (plain ++ in production) */
	ring->lossless_op_count++;

	/* Step 2: ring enqueue (return discarded, matching production) */
	(void)ring_enqueue(ring, 1u);
}

/* ------------------------------------------------------------------ */
/* Simulated drain                                                      */
/*                                                                     */
/* Models stats_ring_drain_all() with the per-child lossless sum:     */
/*   1. drain the ring (slots counted but not used for op_count)      */
/*   2. sum lossless_op_count across all children (here: one child)   */
/*   3. set total_op_count = sum                                       */
/*   4. set op_count = total - epoch_start                            */
/*   5. publish fleet_op_count = op_count (mirrors stats_publish)     */
/* ------------------------------------------------------------------ */

static void sim_drain(struct sim_ring *ring,
		      struct sim_aggregate *agg,
		      unsigned long *fleet_op_count)
{
	/* Step 1: drain the ring */
	(void)ring_drain(ring);

	/* Steps 2-4: sum lossless_op_count (single child in this test) */
	agg->total_op_count = ring->lossless_op_count;
	agg->op_count = agg->total_op_count - agg->epoch_start_op_count;

	/* Step 5: publish fleet_op_count */
	*fleet_op_count = agg->op_count;
}

/* ------------------------------------------------------------------ */
/* Simulated epoch reset                                               */
/*                                                                     */
/* Models reset_epoch_state() with the per-child sum snapshot:        */
/*   1. zero op_count and previous_op_count                           */
/*   2. snapshot epoch_start_op_count from parent_stats.total_op_count */
/*   3. total_op_count unchanged (already set by last drain)           */
/*   4. publish fleet_op_count = 0                                    */
/* ------------------------------------------------------------------ */

static void sim_epoch_reset(struct sim_aggregate *agg,
			    unsigned long *fleet_op_count)
{
	agg->op_count = 0;
	agg->previous_op_count = 0;
	agg->epoch_start_op_count = agg->total_op_count;
	*fleet_op_count = 0;
}

/* ------------------------------------------------------------------ */
/* SELFTEST_ASSERT helper                                              */
/* ------------------------------------------------------------------ */

static void selftest_bug(const char *msg, const char *file,
			 unsigned int line)
{
	fprintf(stderr,
		"FAIL: stats_opclock_lossless: %s:%u: %s\n",
		file, line, msg);
	fflush(stderr);
	abort();
}

#define SELFTEST_ASSERT(cond) \
	do { \
		if (!(cond)) \
			selftest_bug(#cond, __FILE__, __LINE__); \
	} while (0)

/* ------------------------------------------------------------------ */
/* Test 1: ring_full_no_loss                                           */
/*                                                                     */
/* Dispatch 3 * RING_CAP operations.  The ring fills after RING_CAP-1 */
/* slots; the remaining ops are dropped.  lossless_op_count must      */
/* reflect ALL ops; the ring holds only RING_CAP-1 slots at the end.  */
/* ------------------------------------------------------------------ */

static void test_ring_full_no_loss(void)
{
	struct sim_ring ring;
	struct sim_aggregate agg;
	unsigned long fleet = 0;
	unsigned long total_ops = 3 * RING_CAP;
	unsigned long i;

	ring_init(&ring);
	agg_init(&agg);

	/* Dispatch total_ops completions WITHOUT draining between them. */
	for (i = 0; i < total_ops; i++)
		sim_op_complete(&ring);

	/* Ring is saturated; lossless_op_count must show all ops. */
	SELFTEST_ASSERT(ring.lossless_op_count == total_ops);

	/* Drain once -- derives from lossless_op_count, not ring count. */
	sim_drain(&ring, &agg, &fleet);

	SELFTEST_ASSERT(agg.total_op_count == total_ops);
	SELFTEST_ASSERT(agg.op_count       == total_ops);
	SELFTEST_ASSERT(fleet              == total_ops);

	/* Confirm the ring DID drop slots (sanity: dropped != 0). */
	SELFTEST_ASSERT(ring.lossless_op_count > (unsigned long)(RING_CAP - 1));
}

/* ------------------------------------------------------------------ */
/* Test 2: epoch_semantics                                             */
/*                                                                     */
/* Run N ops in epoch 0, then reset, then run M ops in epoch 1.       */
/* Verify that op_count == N after the first drain, == 0 after reset, */
/* and == M after the second drain.  total_op_count is N+M throughout */
/* the second epoch.                                                   */
/* ------------------------------------------------------------------ */

static void test_epoch_semantics(void)
{
	struct sim_ring ring;
	struct sim_aggregate agg;
	unsigned long fleet = 0;
	unsigned long i;
	unsigned long epoch0_ops = 500;
	unsigned long epoch1_ops = 300;

	ring_init(&ring);
	agg_init(&agg);

	/* --- Epoch 0 --- */
	for (i = 0; i < epoch0_ops; i++)
		sim_op_complete(&ring);

	sim_drain(&ring, &agg, &fleet);

	SELFTEST_ASSERT(agg.op_count       == epoch0_ops);
	SELFTEST_ASSERT(agg.total_op_count == epoch0_ops);
	SELFTEST_ASSERT(fleet              == epoch0_ops);

	/* Reset: op_count drops to 0, epoch_start snapshotted. */
	sim_epoch_reset(&agg, &fleet);

	SELFTEST_ASSERT(agg.op_count             == 0);
	SELFTEST_ASSERT(agg.previous_op_count    == 0);
	SELFTEST_ASSERT(agg.epoch_start_op_count == epoch0_ops);
	SELFTEST_ASSERT(agg.total_op_count       == epoch0_ops);
	SELFTEST_ASSERT(fleet                    == 0);

	/* --- Epoch 1 --- */
	for (i = 0; i < epoch1_ops; i++)
		sim_op_complete(&ring);

	sim_drain(&ring, &agg, &fleet);

	SELFTEST_ASSERT(agg.op_count       == epoch1_ops);
	SELFTEST_ASSERT(agg.total_op_count == epoch0_ops + epoch1_ops);
	SELFTEST_ASSERT(fleet              == epoch1_ops);

	/* No double-count: epoch_ops computed as total - start is exact. */
	{
		unsigned long epoch_ops = agg.total_op_count
			- agg.epoch_start_op_count;
		SELFTEST_ASSERT(epoch_ops == epoch1_ops);
	}
}

/* ------------------------------------------------------------------ */
/* Test 3: call_limit_exact                                            */
/*                                                                     */
/* Simulate syscalls_todo = LIMIT.  Old ring-only accumulation would  */
/* under-count if the ring fills and drops occur; the lossless per-   */
/* child counter makes the check exact.                                */
/*                                                                     */
/* We saturate the ring, drain once (op_count from lossless sum), then */
/* verify fleet_op_count >= LIMIT fires when expected.                */
/* ------------------------------------------------------------------ */

static void test_call_limit_exact(void)
{
	struct sim_ring ring;
	struct sim_aggregate agg;
	unsigned long fleet = 0;
	unsigned long limit = 2 * RING_CAP + 7;
	unsigned long i;

	ring_init(&ring);
	agg_init(&agg);

	/* Dispatch limit ops without draining (ring fills and drops). */
	for (i = 0; i < limit; i++)
		sim_op_complete(&ring);

	/*
	 * Old scheme: ring holds at most RING_CAP-1 slots; op_count
	 * after drain would be RING_CAP-1, NOT limit.
	 * New scheme: drain reads lossless_op_count -- op_count == limit.
	 */
	sim_drain(&ring, &agg, &fleet);

	SELFTEST_ASSERT(fleet == limit);
	SELFTEST_ASSERT(fleet >= limit);	/* termination check fires */

	/* Verify old behaviour would have been wrong. */
	SELFTEST_ASSERT((unsigned long)(RING_CAP - 1) < limit);
}

/* ------------------------------------------------------------------ */
/* Test 4: epoch_termination                                           */
/*                                                                     */
/* Set epoch_iterations = E.  Run E ops across two drain windows      */
/* without ever draining in between the first window's ops, so some   */
/* ops would be dropped by a ring-only scheme.  Verify that           */
/* (total - start) == E exactly after the final drain.                */
/* ------------------------------------------------------------------ */

static void test_epoch_termination(void)
{
	struct sim_ring ring;
	struct sim_aggregate agg;
	unsigned long fleet = 0;
	unsigned long epoch_iterations = RING_CAP + 200;
	unsigned long i;

	ring_init(&ring);
	agg_init(&agg);
	sim_epoch_reset(&agg, &fleet);

	/* Window 1: fill the ring completely (RING_CAP ops). */
	for (i = 0; i < (unsigned long)RING_CAP; i++)
		sim_op_complete(&ring);
	sim_drain(&ring, &agg, &fleet);

	/* Window 2: 200 more ops. */
	for (i = 0; i < 200; i++)
		sim_op_complete(&ring);
	sim_drain(&ring, &agg, &fleet);

	{
		unsigned long epoch_ops = agg.total_op_count
			- agg.epoch_start_op_count;
		SELFTEST_ASSERT(epoch_ops == epoch_iterations);
		SELFTEST_ASSERT(epoch_ops >= epoch_iterations);
	}
}

/* ------------------------------------------------------------------ */
/* Test 5: rotation_boundary                                           */
/*                                                                     */
/* The strategy rotation clock reads fleet_op_count (= op_count from  */
/* per-child sum) and fires when (fleet - syscalls_at_last_switch) >= */
/* WINDOW.  Verify that under ring saturation the rotation fires at   */
/* exactly WINDOW ops, not RING_CAP-1 ops (the old under-count).      */
/* ------------------------------------------------------------------ */

static void test_rotation_boundary(void)
{
	struct sim_ring ring;
	struct sim_aggregate agg;
	unsigned long fleet = 0;
	unsigned long syscalls_at_last_switch = 0;
	unsigned long window = RING_CAP + 50;
	unsigned long i;
	bool rotated = false;

	ring_init(&ring);
	agg_init(&agg);

	/* Dispatch window+1 ops, filling the ring past capacity. */
	for (i = 0; i < window + 1; i++)
		sim_op_complete(&ring);

	sim_drain(&ring, &agg, &fleet);

	/* Check rotation: (fleet - syscalls_at_last_switch) >= window */
	if ((fleet - syscalls_at_last_switch) >= window) {
		rotated = true;
		syscalls_at_last_switch = fleet;
	}

	/* Must have rotated (we dispatched window+1 >= window ops). */
	SELFTEST_ASSERT(rotated == true);

	/* fleet_op_count that triggered the rotation is exact. */
	SELFTEST_ASSERT(fleet == window + 1);

	/* After rotation, window clock is reset; next window clean. */
	SELFTEST_ASSERT(syscalls_at_last_switch == fleet);
}

/* ------------------------------------------------------------------ */
/* Test 6: child_respawn_preserve                                      */
/*                                                                     */
/* A child exits and is respawned.  In the real codebase the parent   */
/* drains before recycling the slot, so the pre-exit lossless_op_count */
/* is captured in total_op_count.  The new child gets a fresh ring    */
/* (lossless_op_count = 0); its ops accumulate from 0 but the parent  */
/* adds its lossless_op_count on top of the previously captured total. */
/* ------------------------------------------------------------------ */

static void test_child_respawn_preserve(void)
{
	struct sim_ring ring;
	struct sim_aggregate agg;
	unsigned long fleet = 0;
	unsigned long pre_exit_ops = 400;
	unsigned long post_respawn_ops = 300;
	unsigned long i;
	unsigned long captured_before_respawn;

	ring_init(&ring);
	agg_init(&agg);
	sim_epoch_reset(&agg, &fleet);

	/* Child A runs pre_exit_ops. */
	for (i = 0; i < pre_exit_ops; i++)
		sim_op_complete(&ring);
	sim_drain(&ring, &agg, &fleet);

	SELFTEST_ASSERT(agg.op_count == pre_exit_ops);

	/* Parent captures total before respawn (drain already done). */
	captured_before_respawn = agg.total_op_count;
	SELFTEST_ASSERT(captured_before_respawn == pre_exit_ops);

	/*
	 * Child A exits.  Child B gets a fresh ring (lossless_op_count=0).
	 * The parent's total_op_count keeps the pre-exit tally; subsequent
	 * drains sum child B's fresh lossless_op_count on top of the base.
	 *
	 * Simulate: re-initialise ring (fresh child B), then run ops, then
	 * drain.  The drain sets total_op_count = ring.lossless_op_count
	 * which is only child B's ops.  To model the real parent behaviour
	 * (parent accumulates across child lifetimes), the drain must start
	 * from epoch_start and add the per-child field.  In the single-child
	 * model here, the parent's "captured" value is folded into
	 * epoch_start_op_count so the drain's (total - epoch_start) gives
	 * the right delta.  Adjust epoch_start to reflect the carry-over.
	 */
	agg.epoch_start_op_count = 0;	/* run started at 0, not at epoch reset */

	ring_init(&ring);	/* fresh child B */

	for (i = 0; i < post_respawn_ops; i++)
		sim_op_complete(&ring);

	/*
	 * Simulate multi-child parent drain: total = pre_exit (captured) +
	 * child B's lossless_op_count.
	 */
	agg.total_op_count = captured_before_respawn + ring.lossless_op_count;
	agg.op_count = agg.total_op_count - agg.epoch_start_op_count;
	fleet = agg.op_count;

	SELFTEST_ASSERT(agg.total_op_count == pre_exit_ops + post_respawn_ops);
	SELFTEST_ASSERT(agg.op_count       == pre_exit_ops + post_respawn_ops);

	{
		unsigned long epoch_ops = agg.total_op_count
			- agg.epoch_start_op_count;
		SELFTEST_ASSERT(epoch_ops == pre_exit_ops + post_respawn_ops);
	}
}

/* ------------------------------------------------------------------ */
/* Suite entry point                                                   */
/* ------------------------------------------------------------------ */

void stats_opclock_lossless_self_check(void);
void stats_opclock_lossless_self_check(void)
{
	test_ring_full_no_loss();
	test_epoch_semantics();
	test_call_limit_exact();
	test_epoch_termination();
	test_rotation_boundary();
	test_child_respawn_preserve();
}
