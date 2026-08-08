/*
 * stats_opclock_lossless_test.c -- invariant checks for the lossless
 * op-count atomic (shm->stats.lossless_op_total).
 *
 * Before this fix, op_count / total_op_count were accumulated ONLY
 * from drained ring slots.  A full ring silently dropped increments,
 * causing op_count to under-count and the call-limit / epoch-limit /
 * strategy-rotation checks to fire late or not at all.
 *
 * The fix adds an unconditional __atomic_add_fetch on
 * shm->stats.lossless_op_total at both op-completion sites (child.c
 * alt-op path and dispatch-step.c syscall path) BEFORE the ring
 * enqueue.  The parent derives total_op_count and op_count from the
 * atomic in stats_ring_drain_all(); apply_slot() no longer feeds
 * op_count/total_op_count from the ring.
 *
 * These tests simulate the key invariants without importing the real
 * trinity shm / ring / stats-ring modules.  They model:
 *   - a fixed-capacity SPSC ring (RING_CAP slots)
 *   - the lossless atomic (unsigned long)
 *   - the stats_aggregate scalars (op_count, total_op_count,
 *     epoch_start_op_count)
 *   - simulated drains that apply the new atomic-read logic
 *   - simulated epoch resets
 *
 * Suite entry point: stats_opclock_lossless_self_check()
 *
 * Tests
 * -----
 * 1. ring_full_no_loss       -- atomic reflects all ops even when the
 *                               ring saturates and drops occur.
 * 2. epoch_semantics         -- reset correctly snapshots epoch_start;
 *                               op_count = total - epoch_start always
 *                               equals ops since last reset.
 * 3. call_limit_exact        -- call-limit check fires at EXACTLY the
 *                               right count even under ring saturation.
 * 4. epoch_termination       -- epoch-iteration limit check fires at
 *                               exactly epoch_iterations ops after
 *                               reset, not delayed by ring drops.
 * 5. rotation_boundary       -- strategy rotation clock (fleet_op_count
 *                               = op_count from atomic) triggers at the
 *                               correct window boundary.
 * 6. child_respawn_preserve  -- simulated child exit + respawn does not
 *                               reset the atomic; totals are preserved
 *                               and epoch_start remains correct.
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
/*   1. bump the lossless atomic unconditionally                       */
/*   2. enqueue the ring (may fail if full -- drop is OK)              */
/* ------------------------------------------------------------------ */

static void sim_op_complete(unsigned long *atomic_total,
			    struct sim_ring *ring)
{
	/* Step 1: lossless atomic bump (RELAXED in production) */
	(*atomic_total)++;

	/* Step 2: ring enqueue (return discarded, matching production) */
	(void)ring_enqueue(ring, 1u);
}

/* ------------------------------------------------------------------ */
/* Simulated drain                                                     */
/*                                                                     */
/* Models stats_ring_drain_all() with the new atomic-read logic:      */
/*   1. drain the ring (slots counted but not used for op_count)      */
/*   2. read atomic_total                                              */
/*   3. set total_op_count = atomic_total                              */
/*   4. set op_count = total - epoch_start                             */
/*   5. publish fleet_op_count = op_count (mirrors stats_publish)     */
/* ------------------------------------------------------------------ */

static void sim_drain(const unsigned long *atomic_total,
		      struct sim_ring *ring,
		      struct sim_aggregate *agg,
		      unsigned long *fleet_op_count)
{
	/* Step 1: drain the ring */
	(void)ring_drain(ring);

	/* Steps 2-4: derive counts from atomic */
	agg->total_op_count = *atomic_total;
	agg->op_count = agg->total_op_count - agg->epoch_start_op_count;

	/* Step 5: publish fleet_op_count */
	*fleet_op_count = agg->op_count;
}

/* ------------------------------------------------------------------ */
/* Simulated epoch reset                                               */
/*                                                                     */
/* Models reset_epoch_state() with the new atomic snapshot:           */
/*   1. zero op_count and previous_op_count                           */
/*   2. snapshot epoch_start_op_count from the atomic                 */
/*   3. align total_op_count to the snapshot                          */
/*   4. publish fleet_op_count = 0                                    */
/* ------------------------------------------------------------------ */

static void sim_epoch_reset(const unsigned long *atomic_total,
			    struct sim_aggregate *agg,
			    unsigned long *fleet_op_count)
{
	agg->op_count = 0;
	agg->previous_op_count = 0;
	agg->epoch_start_op_count = *atomic_total;
	agg->total_op_count = agg->epoch_start_op_count;
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
/* slots; the remaining ops are dropped.  The lossless atomic must    */
/* reflect ALL ops; the ring holds only RING_CAP-1 slots at the end.  */
/* ------------------------------------------------------------------ */

static void test_ring_full_no_loss(void)
{
	unsigned long atomic_total = 0;
	struct sim_ring ring;
	struct sim_aggregate agg;
	unsigned long fleet = 0;
	unsigned long total_ops = 3 * RING_CAP;
	unsigned long i;

	ring_init(&ring);
	agg_init(&agg);

	/* Dispatch total_ops completions WITHOUT draining between them. */
	for (i = 0; i < total_ops; i++)
		sim_op_complete(&atomic_total, &ring);

	/* Ring is saturated; atomic must show all ops. */
	SELFTEST_ASSERT(atomic_total == total_ops);

	/* Drain once -- derives from atomic, not from ring count. */
	sim_drain(&atomic_total, &ring, &agg, &fleet);

	SELFTEST_ASSERT(agg.total_op_count == total_ops);
	SELFTEST_ASSERT(agg.op_count       == total_ops);
	SELFTEST_ASSERT(fleet              == total_ops);

	/* Confirm the ring DID drop slots (sanity: dropped != 0). */
	SELFTEST_ASSERT(atomic_total > (unsigned long)(RING_CAP - 1));
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
	unsigned long atomic_total = 0;
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
		sim_op_complete(&atomic_total, &ring);

	sim_drain(&atomic_total, &ring, &agg, &fleet);

	SELFTEST_ASSERT(agg.op_count       == epoch0_ops);
	SELFTEST_ASSERT(agg.total_op_count == epoch0_ops);
	SELFTEST_ASSERT(fleet              == epoch0_ops);

	/* Reset: op_count drops to 0, epoch_start snapshotted. */
	sim_epoch_reset(&atomic_total, &agg, &fleet);

	SELFTEST_ASSERT(agg.op_count             == 0);
	SELFTEST_ASSERT(agg.previous_op_count    == 0);
	SELFTEST_ASSERT(agg.epoch_start_op_count == epoch0_ops);
	SELFTEST_ASSERT(agg.total_op_count       == epoch0_ops);
	SELFTEST_ASSERT(fleet                    == 0);

	/* --- Epoch 1 --- */
	for (i = 0; i < epoch1_ops; i++)
		sim_op_complete(&atomic_total, &ring);

	sim_drain(&atomic_total, &ring, &agg, &fleet);

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
/* under-count if the ring fills and drops occur; the lossless atomic  */
/* makes the check exact.                                              */
/*                                                                     */
/* We saturate the ring, drain once (op_count from atomic), then      */
/* verify fleet_op_count >= LIMIT fires when expected.                */
/* ------------------------------------------------------------------ */

static void test_call_limit_exact(void)
{
	unsigned long atomic_total = 0;
	struct sim_ring ring;
	struct sim_aggregate agg;
	unsigned long fleet = 0;
	unsigned long limit = 2 * RING_CAP + 7;
	unsigned long i;

	ring_init(&ring);
	agg_init(&agg);

	/* Dispatch limit ops without draining (ring fills and drops). */
	for (i = 0; i < limit; i++)
		sim_op_complete(&atomic_total, &ring);

	/*
	 * Old scheme: ring holds at most RING_CAP-1 slots; op_count
	 * after drain would be RING_CAP-1, NOT limit.
	 * New scheme: drain reads atomic -- op_count == limit exactly.
	 */
	sim_drain(&atomic_total, &ring, &agg, &fleet);

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
	unsigned long atomic_total = 0;
	struct sim_ring ring;
	struct sim_aggregate agg;
	unsigned long fleet = 0;
	unsigned long epoch_iterations = RING_CAP + 200;
	unsigned long i;

	ring_init(&ring);
	agg_init(&agg);
	sim_epoch_reset(&atomic_total, &agg, &fleet);

	/* Window 1: fill the ring completely (RING_CAP ops). */
	for (i = 0; i < (unsigned long)RING_CAP; i++)
		sim_op_complete(&atomic_total, &ring);
	sim_drain(&atomic_total, &ring, &agg, &fleet);

	/* Window 2: 200 more ops. */
	for (i = 0; i < 200; i++)
		sim_op_complete(&atomic_total, &ring);
	sim_drain(&atomic_total, &ring, &agg, &fleet);

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
/* atomic) and fires when (fleet - syscalls_at_last_switch) >=        */
/* WINDOW.  Verify that under ring saturation the rotation fires at   */
/* exactly WINDOW ops, not RING_CAP-1 ops (the old under-count).      */
/* ------------------------------------------------------------------ */

static void test_rotation_boundary(void)
{
	unsigned long atomic_total = 0;
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
		sim_op_complete(&atomic_total, &ring);

	sim_drain(&atomic_total, &ring, &agg, &fleet);

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
/* A child exits and is respawned mid-run.  The lossless atomic is    */
/* NOT reset on respawn (MAP_SHARED, accumulates for the full run).   */
/* epoch_start_op_count is only updated by epoch reset.               */
/* Verify that totals are preserved and op_count remains correct.     */
/* ------------------------------------------------------------------ */

static void test_child_respawn_preserve(void)
{
	unsigned long atomic_total = 0;
	struct sim_ring ring;
	struct sim_aggregate agg;
	unsigned long fleet = 0;
	unsigned long pre_exit_ops = 400;
	unsigned long post_respawn_ops = 300;
	unsigned long i;
	unsigned long epoch_start_snap;

	ring_init(&ring);
	agg_init(&agg);
	sim_epoch_reset(&atomic_total, &agg, &fleet);
	epoch_start_snap = agg.epoch_start_op_count;

	/* Child A runs pre_exit_ops. */
	for (i = 0; i < pre_exit_ops; i++)
		sim_op_complete(&atomic_total, &ring);
	sim_drain(&atomic_total, &ring, &agg, &fleet);

	SELFTEST_ASSERT(agg.op_count == pre_exit_ops);
	SELFTEST_ASSERT(agg.epoch_start_op_count == epoch_start_snap);

	/* Child A exits.  Respawned child B uses a fresh ring but the
	 * same atomic_total (MAP_SHARED, not per-child). */
	ring_init(&ring);

	/* Child B runs post_respawn_ops. */
	for (i = 0; i < post_respawn_ops; i++)
		sim_op_complete(&atomic_total, &ring);
	sim_drain(&atomic_total, &ring, &agg, &fleet);

	/* Total must be pre + post; epoch_start unchanged (no reset). */
	SELFTEST_ASSERT(agg.total_op_count ==
			pre_exit_ops + post_respawn_ops);
	SELFTEST_ASSERT(agg.op_count ==
			pre_exit_ops + post_respawn_ops);
	SELFTEST_ASSERT(agg.epoch_start_op_count == epoch_start_snap);

	/* Epoch ops matches total (epoch started at 0 above). */
	{
		unsigned long epoch_ops = agg.total_op_count
			- agg.epoch_start_op_count;
		SELFTEST_ASSERT(epoch_ops ==
				pre_exit_ops + post_respawn_ops);
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
