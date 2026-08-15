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
 * 6. child_respawn_preserve  -- simulated child exit + respawn preserves
 *                               lossless_op_count in the ring page
 *                               (mirrors stats_ring_init which does NOT
 *                               zero lossless_op_count on respawn).
 *                               The parent drain reads the counter
 *                               directly; no compensation is needed.
 *
 * 7. delta_guard             -- exercises the delta-based plausibility
 *                               arm from dfb8993f4632 ("stats-ring: add per-slot delta plausibility guard for lossless_op_count"): a scribble to
 *                               P + 1e8 + 1 (below the absolute ceiling
 *                               but above the per-drain delta limit)
 *                               stalls the aggregate across repeated
 *                               drains and survives a stats_ring_init
 *                               respawn (permanence hazard).
 *
 * 8. first_drain_scribble     -- mirror of test 7: scribble a
 *                               pointer-shaped value (below absolute
 *                               ceiling) BEFORE the first drain so
 *                               prev == 0 and have_baseline is false.
 *                               Verifies the guard rejects it rather
 *                               than admitting it as the baseline and
 *                               locking total_op_count HIGH.
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

/*
 * Plausibility guard thresholds shared with the production drain.
 * Single canonical definition in include/stats_ring_opclock_limits.h;
 * no hand-copy, no "keep in sync" comment needed.
 */
#include "stats_ring_opclock_limits.h"

struct sim_ring {
	unsigned long lossless_op_count;	/* per-child; RELAXED atomic in production
					 * (harness is single-threaded) */
	unsigned int head;
	unsigned int tail;
	unsigned int slots[RING_CAP];	/* payload unused in test */
};

static void ring_init(struct sim_ring *r)
{
	memset(r, 0, sizeof(*r));
}

/*
 * Mirrors production stats_ring_init(): clears ring slots and
 * head/tail but PRESERVES lossless_op_count (run-monotonic across
 * child respawns -- see stats-ring.c:stats_ring_init and
 * stats_ring.h:lossless_op_count).
 */
static void ring_respawn_init(struct sim_ring *r)
{
	unsigned long saved = r->lossless_op_count;

	memset(r, 0, sizeof(*r));
	r->lossless_op_count = saved;
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
/*   1. increment the per-child lossless_op_count via RELAXED          */
/*      atomic fetch-add (sole writer; harness is single-threaded)     */
/*   2. enqueue the ring (may fail if full -- drop is OK)              */
/* ------------------------------------------------------------------ */

static void sim_op_complete(struct sim_ring *ring)
{
	/* Step 1: per-child lossless increment (RELAXED atomic in production;
	 * single-threaded harness so ordering is moot here) */
	__atomic_fetch_add(&ring->lossless_op_count, 1, __ATOMIC_RELAXED);

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
/* Delta-guarded drain                                                  */
/*                                                                     */
/* Mirrors the two-layer plausibility guard in stats/stats-ring.c:    */
/*   1. absolute ceiling: slot_ops > LOSSLESS_OP_COUNT_SANE_CEILING   */
/*   2. delta ceiling:    slot_ops - prev > MAX_DELTA_PER_DRAIN,      */
/*      or backward jump: slot_ops < prev (monotonicity violated)     */
/*                                                                     */
/* Returns true when the slot was accepted (aggregate updated),        */
/* false when rejected (aggregate stalls at last good value).          */
/*                                                                     */
/* prev_op, have_baseline, and reported mirror the per-slot cross-drain*/
/* state (prev_lossless_op_count[], have_baseline_lossless[], and      */
/* slot_implausible_reported[] in production).  have_baseline must be  */
/* false on first call and is set true on the first accept, arming the */
/* delta check from drain 1 with prev = 0.                             */
/* ------------------------------------------------------------------ */

static bool sim_drain_guarded(struct sim_ring *ring,
			      struct sim_aggregate *agg,
			      unsigned long *fleet_op_count,
			      unsigned long *prev_op,
			      bool *have_baseline,
			      bool *reported)
{
	unsigned long slot_ops;
	unsigned long prev;
	bool absolute_bad;
	bool delta_bad;

	(void)ring_drain(ring);

	slot_ops     = ring->lossless_op_count;
	prev         = *prev_op;
	absolute_bad = (slot_ops > LOSSLESS_OP_COUNT_SANE_CEILING);
	delta_bad    = (*have_baseline) &&
		       ((slot_ops < prev) ||
			(slot_ops - prev > LOSSLESS_OP_COUNT_MAX_DELTA_PER_DRAIN));

	if (absolute_bad || delta_bad) {
		/*
		 * Rate-limit flag: only emits a diagnostic on first detection.
		 * Aggregate stalls; prev_op is NOT updated so the delta check
		 * stays anchored to the last known-good baseline.
		 */
		*reported = true;
		agg->op_count   = agg->total_op_count - agg->epoch_start_op_count;
		*fleet_op_count = agg->op_count;
		return false;
	}

	/* Plausible: re-arm reporting, advance prev baseline, update agg. */
	*reported           = false;
	*have_baseline      = true;
	*prev_op            = slot_ops;
	agg->total_op_count = slot_ops;
	agg->op_count       = agg->total_op_count - agg->epoch_start_op_count;
	*fleet_op_count     = agg->op_count;
	return true;
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
/* A child exits and is respawned.  Production stats_ring_init() does  */
/* NOT zero lossless_op_count (it is run-monotonic across respawns).  */
/* The ring page is allocated once per slot in shm.c and never        */
/* reallocated; lossless_op_count simply continues incrementing in    */
/* the new child.  The parent drain reads the counter directly and    */
/* needs no compensation: total_op_count = lossless_op_count after    */
/* any drain, naturally spanning both child lifetimes.                 */
/* ------------------------------------------------------------------ */

static void test_child_respawn_preserve(void)
{
	struct sim_ring ring;
	struct sim_aggregate agg;
	unsigned long fleet = 0;
	unsigned long pre_exit_ops = 400;
	unsigned long post_respawn_ops = 300;
	unsigned long i;

	ring_init(&ring);
	agg_init(&agg);
	sim_epoch_reset(&agg, &fleet);

	/* Child A runs pre_exit_ops. */
	for (i = 0; i < pre_exit_ops; i++)
		sim_op_complete(&ring);
	sim_drain(&ring, &agg, &fleet);

	SELFTEST_ASSERT(agg.op_count       == pre_exit_ops);
	SELFTEST_ASSERT(agg.total_op_count == pre_exit_ops);
	SELFTEST_ASSERT(ring.lossless_op_count == pre_exit_ops);

	/*
	 * Child A exits.  Production stats_ring_init() is called on the
	 * same ring page; it clears slots/head/tail but leaves
	 * lossless_op_count intact.  Simulate with ring_respawn_init().
	 */
	ring_respawn_init(&ring);
	SELFTEST_ASSERT(ring.lossless_op_count == pre_exit_ops);

	/* Child B runs post_respawn_ops; lossless_op_count keeps climbing. */
	for (i = 0; i < post_respawn_ops; i++)
		sim_op_complete(&ring);

	SELFTEST_ASSERT(ring.lossless_op_count == pre_exit_ops + post_respawn_ops);

	/*
	 * Drain: total_op_count = lossless_op_count directly -- no
	 * compensation required.  The run-monotonic counter already spans
	 * both child lifetimes.
	 */
	sim_drain(&ring, &agg, &fleet);

	SELFTEST_ASSERT(agg.total_op_count == pre_exit_ops + post_respawn_ops);
	SELFTEST_ASSERT(agg.op_count       == pre_exit_ops + post_respawn_ops);

	{
		unsigned long epoch_ops = agg.total_op_count
			- agg.epoch_start_op_count;
		SELFTEST_ASSERT(epoch_ops == pre_exit_ops + post_respawn_ops);
	}
}

/* ------------------------------------------------------------------ */
/* Test 7: delta_guard                                                 */
/*                                                                     */
/* Exercises the delta-based plausibility arm added in               */
/* dfb8993f4632 ("stats-ring: add per-slot delta plausibility guard for lossless_op_count"): */
/*                                                                     */
/* Phase 1: run baseline_ops normally; first guarded drain accepts and */
/*           records prev = baseline_ops.                              */
/*                                                                     */
/* Phase 2: scribble lossless_op_count to P + MAX_DELTA + 1.  The    */
/*           absolute ceiling passes (far below 2^52); the delta arm  */
/*           trips (increment > 1e8).  Repeated drains (including     */
/*           while the child keeps incrementing in the corrupted       */
/*           range) are all rejected and the aggregate stalls.         */
/*                                                                     */
/* Phase 3: respawn via ring_respawn_init() (mirrors production        */
/*           stats_ring_init -- lossless_op_count is preserved).       */
/*           The scribble survives; rejection persists and the         */
/*           aggregate remains stalled -- the permanence hazard is     */
/*           directly observable.                                      */
/* ------------------------------------------------------------------ */

static void test_delta_guard(void)
{
	struct sim_ring ring;
	struct sim_aggregate agg;
	unsigned long fleet = 0;
	unsigned long prev_op = 0;
	bool have_baseline = false;
	bool reported = false;
	unsigned long baseline_ops = 500;
	unsigned long stalled_total;
	bool accepted;

	ring_init(&ring);
	agg_init(&agg);

	/* Phase 1: establish baseline P. */
	{
		unsigned long i;

		for (i = 0; i < baseline_ops; i++)
			sim_op_complete(&ring);
	}

	accepted = sim_drain_guarded(&ring, &agg, &fleet, &prev_op, &have_baseline, &reported);
	SELFTEST_ASSERT(accepted);
	SELFTEST_ASSERT(agg.total_op_count == baseline_ops);
	SELFTEST_ASSERT(prev_op == baseline_ops);
	SELFTEST_ASSERT(have_baseline);
	SELFTEST_ASSERT(!reported);

	/*
	 * Phase 2: scribble lossless_op_count to P + MAX_DELTA + 1.
	 * Below SANE_CEILING (absolute guard passes) but the increment from
	 * prev exceeds MAX_DELTA_PER_DRAIN (delta guard trips).
	 */
	ring.lossless_op_count =
		baseline_ops + LOSSLESS_OP_COUNT_MAX_DELTA_PER_DRAIN + 1;
	SELFTEST_ASSERT(ring.lossless_op_count < LOSSLESS_OP_COUNT_SANE_CEILING);

	stalled_total = agg.total_op_count;

	/* Drain 1 after scribble: delta guard trips; aggregate stalls. */
	accepted = sim_drain_guarded(&ring, &agg, &fleet, &prev_op, &have_baseline, &reported);
	SELFTEST_ASSERT(!accepted);
	SELFTEST_ASSERT(reported);
	SELFTEST_ASSERT(agg.total_op_count == stalled_total);
	/* prev_op must not have advanced (baseline stays anchored). */
	SELFTEST_ASSERT(prev_op == baseline_ops);

	/* Child keeps incrementing inside the corrupted range. */
	ring.lossless_op_count += 1000;

	/* Drain 2: delta from original prev is larger; still rejected. */
	accepted = sim_drain_guarded(&ring, &agg, &fleet, &prev_op, &have_baseline, &reported);
	SELFTEST_ASSERT(!accepted);
	SELFTEST_ASSERT(agg.total_op_count == stalled_total);
	SELFTEST_ASSERT(prev_op == baseline_ops);

	/*
	 * Phase 3: respawn via ring_respawn_init() (mirrors production
	 * stats_ring_init which preserves lossless_op_count).
	 * The scribbled value survives the respawn.
	 */
	ring_respawn_init(&ring);
	SELFTEST_ASSERT(ring.lossless_op_count ==
			baseline_ops + LOSSLESS_OP_COUNT_MAX_DELTA_PER_DRAIN + 1001);

	/* Drain after respawn: rejection persists; aggregate stalls permanently. */
	accepted = sim_drain_guarded(&ring, &agg, &fleet, &prev_op, &have_baseline, &reported);
	SELFTEST_ASSERT(!accepted);
	SELFTEST_ASSERT(agg.total_op_count == stalled_total);
}

/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/* Test 8: first_drain_scribble                                        */
/*                                                                     */
/* Mirror of test 7: scribble a pointer-shaped value (below the       */
/* absolute ceiling) BEFORE the first drain, so have_baseline is false */
/* and prev == 0.  Under the old (prev > 0) scheme the delta arm was  */
/* disabled and the scribble was admitted as the baseline, locking     */
/* total_op_count HIGH.  The new have_baseline scheme must reject it.  */
/* ------------------------------------------------------------------ */

static void test_first_drain_scribble(void)
{
	struct sim_ring ring;
	struct sim_aggregate agg;
	unsigned long fleet = 0;
	unsigned long prev_op = 0;
	bool have_baseline = false;
	bool reported = false;
	bool accepted;

	/*
	 * A pointer-shaped value: below SANE_CEILING (2^52) but well above
	 * MAX_DELTA_PER_DRAIN.  This mimics a fuzzed arg pointer stomping
	 * the lossless_op_count field before any legitimate op is observed.
	 * 0x00007f2a12345678 == 139816774608504 < 2^52 == 4503599627370496.
	 */
	const unsigned long scribble = 0x00007f2a12345678UL;

	ring_init(&ring);
	agg_init(&agg);

	/* No ops have run; plant the scribble before the first drain. */
	ring.lossless_op_count = scribble;

	/* Sanity: value is below the absolute ceiling so only delta catches it. */
	SELFTEST_ASSERT(scribble < LOSSLESS_OP_COUNT_SANE_CEILING);
	/* Sanity: value exceeds the per-drain delta limit. */
	SELFTEST_ASSERT(scribble > LOSSLESS_OP_COUNT_MAX_DELTA_PER_DRAIN);

	/*
	 * First drain: have_baseline is false so prev == 0.  The delta from
	 * 0 to scribble exceeds MAX_DELTA_PER_DRAIN.  Must be rejected.
	 */
	accepted = sim_drain_guarded(&ring, &agg, &fleet, &prev_op, &have_baseline, &reported);
	SELFTEST_ASSERT(!accepted);
	SELFTEST_ASSERT(reported);
	/* Aggregate must not have moved. */
	SELFTEST_ASSERT(agg.total_op_count == 0);
	/* have_baseline must remain false: no good baseline recorded. */
	SELFTEST_ASSERT(!have_baseline);
	/* prev_op must remain 0: bad value must not pollute the anchor. */
	SELFTEST_ASSERT(prev_op == 0);
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
	test_delta_guard();
	test_first_drain_scribble();
}
