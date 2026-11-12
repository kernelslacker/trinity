/*
 * Checks for the per-slot plausibility guard the drain folds each child's
 * lossless op count (stats_ring.lossless_op_count) through, production's
 * opclock_slot_observe() (include/stats_ring_opclock_limits.h).  A simulated
 * SPSC ring, counter and aggregate scalars stand in for the real shm and
 * ring modules.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Simulated ring                                                      */
/* ------------------------------------------------------------------ */

/* Capacity matches the real STATS_RING_SIZE. */
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
/* Delta-guarded drain                                                  */
/*                                                                     */
/* Folds the reading, taken at now_ms, through opclock_slot_observe(), */
/* the same per-slot guard and sum stats_ring_drain_all() uses        */
/* (include/stats_ring_opclock_limits.h): a delta above               */
/* MAX_DELTA_PER_DRAIN or a backward step makes the slot untrusted    */
/* until it comes back into range or rebases.                         */
/*                                                                     */
/* Returns the guard's verdict.  With one simulated ring the fleet    */
/* sum is this slot's contribution, so an untrusted slot stalls the   */
/* aggregate at its last good total.  *emissions counts the one-shot  */
/* diagnostics production would print.                                 */
/* ------------------------------------------------------------------ */

/* The idle main-loop tick, the usual interval between drains. */
#define TICK_MS	25UL

static enum opclock_verdict sim_drain_guarded(struct sim_ring *ring,
					      struct sim_aggregate *agg,
					      unsigned long *fleet_op_count,
					      struct opclock_slot *slot,
					      unsigned long now_ms,
					      int *emissions)
{
	enum opclock_verdict v;

	(void)ring_drain(ring);

	agg->total_op_count = opclock_slot_observe(slot, ring->lossless_op_count,
						   now_ms, &v);
	if (v == OPCLOCK_NEWLY_REJECTED)
		(*emissions)++;
	agg->op_count       = agg->total_op_count - agg->epoch_start_op_count;
	*fleet_op_count     = agg->op_count;
	return v;
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
/* Test 1: delta_guard                                                 */
/*                                                                     */
/* Exercises the per-slot delta plausibility guard for                */
/* lossless_op_count:                                                  */
/*                                                                     */
/* Phase 1: run baseline_ops normally; first guarded drain accepts and */
/*           records prev = baseline_ops.                              */
/*                                                                     */
/* Phase 2: scribble lossless_op_count to P + MAX_DELTA + 1, below    */
/*           2^52 but an increment above 1e8, so the delta arm trips. */
/*           Repeated drains (including while the child keeps         */
/*           incrementing in the corrupted range) are all rejected    */
/*           and the aggregate stalls.                                 */
/*                                                                     */
/* Phase 3: respawn via ring_respawn_init() (mirrors production        */
/*           stats_ring_init -- lossless_op_count is preserved).       */
/*           The scribble survives and the rejection persists.         */
/*                                                                     */
/* Phase 4: the child keeps counting from the scribbled value.  Once  */
/*           that climb has lasted LOSSLESS_OP_COUNT_REBASE_SPAN_MS   */
/*           the slot rebases, and later ops reach the aggregate      */
/*           again; the scribbled magnitude never does.               */
/* ------------------------------------------------------------------ */

static void test_delta_guard(void)
{
	struct sim_ring ring;
	struct sim_aggregate agg;
	unsigned long fleet = 0;
	struct opclock_slot slot = { 0 };
	unsigned long baseline_ops = 500;
	unsigned long stalled_total;
	unsigned long now = 0;
	unsigned long scribbled_at;
	enum opclock_verdict v;

	ring_init(&ring);
	agg_init(&agg);

	/* Phase 1: establish baseline P. */
	{
		unsigned long i;

		for (i = 0; i < baseline_ops; i++)
			sim_op_complete(&ring);
	}

	int emissions = 0;

	now += TICK_MS;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
	SELFTEST_ASSERT(v == OPCLOCK_ACCEPTED);
	SELFTEST_ASSERT(agg.total_op_count == baseline_ops);
	SELFTEST_ASSERT(slot.prev == baseline_ops);
	SELFTEST_ASSERT(!slot.untrusted);

	/*
	 * Phase 2: scribble lossless_op_count to P + MAX_DELTA + 1.
	 * Below SANE_CEILING, but the increment from prev exceeds
	 * MAX_DELTA_PER_DRAIN (delta guard trips).
	 */
	ring.lossless_op_count =
		baseline_ops + LOSSLESS_OP_COUNT_MAX_DELTA_PER_DRAIN + 1;
	SELFTEST_ASSERT(ring.lossless_op_count < LOSSLESS_OP_COUNT_SANE_CEILING);

	stalled_total = agg.total_op_count;

	/* Drain 1 after scribble: delta guard trips; aggregate stalls. */
	now += TICK_MS;
	scribbled_at = now;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
	SELFTEST_ASSERT(v != OPCLOCK_ACCEPTED);
	SELFTEST_ASSERT(slot.untrusted);
	SELFTEST_ASSERT(agg.total_op_count == stalled_total);
	/* slot.prev must not have advanced (baseline stays anchored). */
	SELFTEST_ASSERT(slot.prev == baseline_ops);

	/* Child keeps incrementing inside the corrupted range. */
	ring.lossless_op_count += 1000;

	/* Drain 2: delta from original prev is larger; still rejected. */
	now += TICK_MS;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
	SELFTEST_ASSERT(v != OPCLOCK_ACCEPTED);
	SELFTEST_ASSERT(agg.total_op_count == stalled_total);
	SELFTEST_ASSERT(slot.prev == baseline_ops);

	/*
	 * Phase 3: respawn via ring_respawn_init() (mirrors production
	 * stats_ring_init which preserves lossless_op_count).
	 * The scribbled value survives the respawn.
	 */
	ring_respawn_init(&ring);
	SELFTEST_ASSERT(ring.lossless_op_count ==
			baseline_ops + LOSSLESS_OP_COUNT_MAX_DELTA_PER_DRAIN + 1001);

	/* Drain after respawn: rejection persists; aggregate stays stalled. */
	now += TICK_MS;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
	SELFTEST_ASSERT(v != OPCLOCK_ACCEPTED);
	SELFTEST_ASSERT(agg.total_op_count == stalled_total);

	/*
	 * Rate-limit coverage: across three rejecting drains, the emission
	 * counter must be exactly 1.  slot.untrusted was false only at the
	 * first rejection (drain 1); drains 2 and 3 see it set and must not
	 * fire again.  This fails if the one-shot latch is absent or the
	 * guard fires more than once.
	 */
	SELFTEST_ASSERT(emissions == 1);

	/*
	 * Phase 4.  The climb began at the scribble.  The drain that brings
	 * it to LOSSLESS_OP_COUNT_REBASE_SPAN_MS rebases the slot on that
	 * reading, adding nothing; only ops after it count.
	 */
	while (now + TICK_MS - scribbled_at < LOSSLESS_OP_COUNT_REBASE_SPAN_MS) {
		now += TICK_MS;
		ring.lossless_op_count += 100;
		v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
		SELFTEST_ASSERT(v == OPCLOCK_REJECTED);
		SELFTEST_ASSERT(agg.total_op_count == stalled_total);
	}
	now += TICK_MS;
	ring.lossless_op_count += 100;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
	SELFTEST_ASSERT(v == OPCLOCK_REBASED);
	SELFTEST_ASSERT(!slot.untrusted);
	SELFTEST_ASSERT(agg.total_op_count == stalled_total);

	now += TICK_MS;
	ring.lossless_op_count += 250;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
	SELFTEST_ASSERT(v == OPCLOCK_ACCEPTED);
	SELFTEST_ASSERT(agg.total_op_count == stalled_total + 250);
	SELFTEST_ASSERT(emissions == 1);
}

/* ------------------------------------------------------------------ */
/* Test 2: first_drain_scribble                                        */
/*                                                                     */
/* Mirror of test 1: scribble a pointer-shaped value (below the       */
/* absolute ceiling) BEFORE the first drain, so prev == 0.  A guard   */
/* that only engaged once prev > 0 would admit the scribble as the    */
/* baseline and lock total_op_count HIGH; this one must reject it.    */
/* ------------------------------------------------------------------ */

static void test_first_drain_scribble(void)
{
	struct sim_ring ring;
	struct sim_aggregate agg;
	unsigned long fleet = 0;
	struct opclock_slot slot = { 0 };
	enum opclock_verdict v;

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

	/* Sanity: below the absolute ceiling; the delta guard rejects it. */
	SELFTEST_ASSERT(scribble < LOSSLESS_OP_COUNT_SANE_CEILING);
	/* Sanity: value exceeds the per-drain delta limit. */
	SELFTEST_ASSERT(scribble > LOSSLESS_OP_COUNT_MAX_DELTA_PER_DRAIN);

	/*
	 * First drain: prev == 0 (calloc init).  The delta from 0 to scribble
	 * exceeds MAX_DELTA_PER_DRAIN.  The guard is unconditional so this
	 * must be rejected even though no previous accepted drain exists.
	 */
	int emissions8 = 0;

	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, TICK_MS, &emissions8);
	SELFTEST_ASSERT(v != OPCLOCK_ACCEPTED);
	SELFTEST_ASSERT(slot.untrusted);
	/* Aggregate must not have moved. */
	SELFTEST_ASSERT(agg.total_op_count == 0);
	/* slot.prev must remain 0: bad value must not pollute the anchor. */
	SELFTEST_ASSERT(slot.prev == 0);
}

/* ------------------------------------------------------------------ */
/* Test 3: transient_and_downward_scribbles                            */
/*                                                                     */
/* One wild reading followed by the true value costs nothing: the     */
/* true value is back within MAX_DELTA_PER_DRAIN of prev and counts   */
/* at once.  A scribble below prev is a backward step: the aggregate  */
/* holds instead of going backwards, and the slot rebases once the    */
/* counter has climbed for LOSSLESS_OP_COUNT_REBASE_SPAN_MS, long     */
/* before it would climb back past the old value on its own.          */
/* ------------------------------------------------------------------ */

static void test_transient_and_downward_scribbles(void)
{
	struct sim_ring ring;
	struct sim_aggregate agg;
	struct opclock_slot slot = { 0 };
	unsigned long fleet = 0;
	unsigned long now = 0;
	unsigned long held, scribbled_at;
	int emissions = 0;
	enum opclock_verdict v;

	ring_init(&ring);
	agg_init(&agg);

	ring.lossless_op_count = 1000000;
	now += TICK_MS;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
	SELFTEST_ASSERT(v == OPCLOCK_ACCEPTED);
	held = agg.total_op_count;

	ring.lossless_op_count = 0x00007f2a12345678UL;
	now += TICK_MS;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
	SELFTEST_ASSERT(v == OPCLOCK_NEWLY_REJECTED);
	SELFTEST_ASSERT(agg.total_op_count == held);

	ring.lossless_op_count = 1000000 + 300;
	now += TICK_MS;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
	SELFTEST_ASSERT(v == OPCLOCK_ACCEPTED);
	SELFTEST_ASSERT(!slot.untrusted);
	SELFTEST_ASSERT(agg.total_op_count == held + 300);
	held = agg.total_op_count;

	ring.lossless_op_count = 10;
	now += TICK_MS;
	scribbled_at = now;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
	SELFTEST_ASSERT(v == OPCLOCK_NEWLY_REJECTED);
	SELFTEST_ASSERT(agg.total_op_count == held);

	while (now + TICK_MS - scribbled_at < LOSSLESS_OP_COUNT_REBASE_SPAN_MS) {
		now += TICK_MS;
		ring.lossless_op_count += 50;
		v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
		SELFTEST_ASSERT(v == OPCLOCK_REJECTED);
		SELFTEST_ASSERT(agg.total_op_count == held);
	}
	now += TICK_MS;
	ring.lossless_op_count += 50;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
	SELFTEST_ASSERT(v == OPCLOCK_REBASED);

	now += TICK_MS;
	ring.lossless_op_count += 50;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
	SELFTEST_ASSERT(v == OPCLOCK_ACCEPTED);
	SELFTEST_ASSERT(agg.total_op_count == held + 50);
	SELFTEST_ASSERT(emissions == 2);
}

/* ------------------------------------------------------------------ */
/* Test 4: over_ceiling_scribble_rebases                               */
/*                                                                     */
/* The observed wild value 0x693bb2ae5ba348af sits above the absolute */
/* ceiling.  The slot rebases on it once the counter climbs           */
/* plausibly, then stays trusted: only deltas reach the sum, so the   */
/* ceiling no longer judges a rebased slot's raw reading.             */
/* ------------------------------------------------------------------ */

static void test_over_ceiling_scribble_rebases(void)
{
	struct sim_ring ring;
	struct sim_aggregate agg;
	struct opclock_slot slot = { 0 };
	unsigned long fleet = 0;
	unsigned long now = 0;
	unsigned long scribbled_at;
	unsigned int i;
	int emissions = 0;
	enum opclock_verdict v;

	ring_init(&ring);
	agg_init(&agg);

	ring.lossless_op_count = 500;
	now += TICK_MS;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
	SELFTEST_ASSERT(v == OPCLOCK_ACCEPTED);

	ring.lossless_op_count = 0x693bb2ae5ba348afUL;
	SELFTEST_ASSERT(ring.lossless_op_count > LOSSLESS_OP_COUNT_SANE_CEILING);
	now += TICK_MS;
	scribbled_at = now;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
	SELFTEST_ASSERT(v == OPCLOCK_NEWLY_REJECTED);

	while (now + TICK_MS - scribbled_at < LOSSLESS_OP_COUNT_REBASE_SPAN_MS) {
		now += TICK_MS;
		ring.lossless_op_count += 7;
		v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
		SELFTEST_ASSERT(v == OPCLOCK_REJECTED);
	}
	now += TICK_MS;
	ring.lossless_op_count += 7;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
	SELFTEST_ASSERT(v == OPCLOCK_REBASED);
	SELFTEST_ASSERT(agg.total_op_count == 500);

	for (i = 0; i < 4; i++) {
		now += TICK_MS;
		ring.lossless_op_count += 7;
		v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
		SELFTEST_ASSERT(v == OPCLOCK_ACCEPTED);
	}
	SELFTEST_ASSERT(agg.total_op_count == 500 + 4 * 7);
	SELFTEST_ASSERT(emissions == 1);
}

/* ------------------------------------------------------------------ */
/* Test 5: clock_scribble_never_counts                                 */
/*                                                                     */
/* A scribble source keeps writing a nanosecond clock into the        */
/* counter while the child counts normally in between.  None of the   */
/* clock's movement may reach the sum at any drain cadence: drains    */
/* run every main-loop tick, 25 ms when idle but back to back on a    */
/* busy loop.  Written more often than LOSSLESS_OP_COUNT_REBASE_SPAN_MS, */
/* every climb long enough to rebase contains a write and runs at     */
/* clock rate, so the slot never rebases.  Written less often, it     */
/* rebases between writes, each write jumps past MAX_DELTA_PER_DRAIN  */
/* and is rejected, and the slot stops rebasing after                 */
/* LOSSLESS_OP_COUNT_MAX_REBASES.                                      */
/* ------------------------------------------------------------------ */

#define CLOCK_NS_BASE		1700000000000000000UL
#define CHILD_OPS_PER_MS	10UL

/* Run the scribbler for run_ms and return how often the slot rebased. */
static unsigned int clock_scribble_run(unsigned long drain_ms,
				       unsigned long write_ms,
				       unsigned long run_ms)
{
	struct sim_ring ring;
	struct sim_aggregate agg;
	struct opclock_slot slot = { 0 };
	unsigned long fleet = 0;
	unsigned long now, next_write = write_ms, child_ops = 0;
	unsigned int rebases = 0;
	int emissions = 0;
	enum opclock_verdict v;

	ring_init(&ring);
	agg_init(&agg);

	ring.lossless_op_count = 500;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, 0, &emissions);
	SELFTEST_ASSERT(v == OPCLOCK_ACCEPTED);

	for (now = drain_ms; now <= run_ms; now += drain_ms) {
		if (now >= next_write) {
			ring.lossless_op_count = CLOCK_NS_BASE + now * 1000000UL;
			next_write += write_ms;
		} else {
			ring.lossless_op_count += drain_ms * CHILD_OPS_PER_MS;
			child_ops += drain_ms * CHILD_OPS_PER_MS;
		}
		v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
		if (v == OPCLOCK_REBASED)
			rebases++;
		/* Only ops the child really counted may reach the sum. */
		SELFTEST_ASSERT(agg.total_op_count <= 500 + child_ops);
	}
	return rebases;
}

static void test_clock_scribble_never_counts(void)
{
	/* Written every 50 ms, drained back to back or at the idle tick. */
	SELFTEST_ASSERT(clock_scribble_run(1, 50, 5000) == 0);
	SELFTEST_ASSERT(clock_scribble_run(TICK_MS, 50, 5000) == 0);

	/* Written every 400 ms: rebases between writes, then gives up. */
	SELFTEST_ASSERT(clock_scribble_run(1, 400, 10000) ==
			LOSSLESS_OP_COUNT_MAX_REBASES);
}

/* ------------------------------------------------------------------ */
/* Test 6: second_run_restarts_the_span                                */
/*                                                                     */
/* A slot that rebased and is then scribbled again starts a new       */
/* implausible run: a second diagnostic, and a full                    */
/* LOSSLESS_OP_COUNT_REBASE_SPAN_MS climb before it rebases again --   */
/* nothing carries over from the first run.                            */
/* ------------------------------------------------------------------ */

static void test_second_run_restarts_the_span(void)
{
	struct sim_ring ring;
	struct sim_aggregate agg;
	struct opclock_slot slot = { 0 };
	unsigned long fleet = 0;
	unsigned long now = 0;
	unsigned long scribbled_at;
	unsigned int run;
	int emissions = 0;
	enum opclock_verdict v;

	ring_init(&ring);
	agg_init(&agg);

	ring.lossless_op_count = 500;
	now += TICK_MS;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
	SELFTEST_ASSERT(v == OPCLOCK_ACCEPTED);

	for (run = 1; run <= 2; run++) {
		ring.lossless_op_count += 0x00007f0000000000UL;
		now += TICK_MS;
		scribbled_at = now;
		v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
		SELFTEST_ASSERT(v == OPCLOCK_NEWLY_REJECTED);
		SELFTEST_ASSERT(emissions == (int)run);

		while (now + TICK_MS - scribbled_at < LOSSLESS_OP_COUNT_REBASE_SPAN_MS) {
			now += TICK_MS;
			ring.lossless_op_count += 10;
			v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
			SELFTEST_ASSERT(v == OPCLOCK_REJECTED);
		}
		now += TICK_MS;
		ring.lossless_op_count += 10;
		v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
		SELFTEST_ASSERT(v == OPCLOCK_REBASED);

		now += TICK_MS;
		ring.lossless_op_count += 40;
		v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
		SELFTEST_ASSERT(v == OPCLOCK_ACCEPTED);
		SELFTEST_ASSERT(agg.total_op_count == 500 + run * 40);
	}
}

/* ------------------------------------------------------------------ */
/* Test 7: wobbling_scribble_never_rebases                             */
/*                                                                     */
/* A scribbler that keeps rewriting the counter between two nearby    */
/* values never climbs monotonically: every backward step restarts    */
/* the climb, so the slot never rebases onto it.                       */
/* ------------------------------------------------------------------ */

static void test_wobbling_scribble_never_rebases(void)
{
	struct sim_ring ring;
	struct sim_aggregate agg;
	struct opclock_slot slot = { 0 };
	unsigned long fleet = 0;
	unsigned long now = 0;
	unsigned long i;
	int emissions = 0;
	enum opclock_verdict v;

	ring_init(&ring);
	agg_init(&agg);

	ring.lossless_op_count = 500;
	now += TICK_MS;
	v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
	SELFTEST_ASSERT(v == OPCLOCK_ACCEPTED);

	for (i = 0; i < 4 * LOSSLESS_OP_COUNT_REBASE_SPAN_MS / TICK_MS; i++) {
		ring.lossless_op_count = 0x00007f2a12345678UL + (i & 1) * 1000;
		now += TICK_MS;
		v = sim_drain_guarded(&ring, &agg, &fleet, &slot, now, &emissions);
		SELFTEST_ASSERT(v != OPCLOCK_REBASED);
		SELFTEST_ASSERT(agg.total_op_count == 500);
	}
	SELFTEST_ASSERT(emissions == 1);
}

/* ------------------------------------------------------------------ */
/* Suite entry point                                                   */
/* ------------------------------------------------------------------ */

void stats_opclock_lossless_self_check(void);
void stats_opclock_lossless_self_check(void)
{
	test_delta_guard();
	test_first_drain_scribble();
	test_transient_and_downward_scribbles();
	test_over_ceiling_scribble_rebases();
	test_clock_scribble_never_counts();
	test_second_run_restarts_the_span();
	test_wobbling_scribble_never_rebases();
}
