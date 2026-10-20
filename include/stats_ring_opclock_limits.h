#pragma once

#include <stdbool.h>

/*
 * Plausibility guard for the per-child lossless op counter
 * (stats_ring.lossless_op_count): the thresholds, and the per-slot fold
 * the parent's drain applies to every reading.  Canonical home for both
 * so the production drain (stats/stats-ring.c) and the invariant
 * self-test (tests/stats_opclock_lossless_test.c) run the same code
 * without copying it or maintaining a "keep in sync" comment.
 *
 * LOSSLESS_OP_COUNT_SANE_CEILING (absolute): any per-child value above
 * 2^52 (~4.5e15) is unconditionally treated as scribbled shm and
 * dropped.  This catches the observed garbage value 0x693bb2ae5ba348af
 * (~2^62.7) and anything above the ceiling.  2^52 is many orders of
 * magnitude above any realistic run total (100k ops/sec/child × years
 * < 10^13).
 *
 * LOSSLESS_OP_COUNT_MAX_DELTA_PER_DRAIN (delta): lossless_op_count is
 * run-monotonic (never reset across child respawns).  A drain-to-drain
 * increment larger than this constant is implausible regardless of the
 * absolute value, and catches the entire class of garbage values in the
 * range [real_total, 2^52) that the absolute ceiling misses.  1e8 ops
 * per drain interval is a 100× safety margin over the fastest realistic
 * child (1M syscalls/sec × ~1s drain cadence = 1M delta).
 *
 * Both checks share one action: skip accumulation and emit a one-shot
 * diagnostic (rate-limited to once per implausible run via
 * opclock_slot.untrusted so lossless_slot_implausible counts distinct
 * corrupted slots, not the slot × drain re-observation product).
 *
 * This header depends only on <stdbool.h> and may be included from
 * standalone test files that do not pull in the full stats_ring.h
 * include graph.
 */
#define LOSSLESS_OP_COUNT_SANE_CEILING        (1UL << 52)
#define LOSSLESS_OP_COUNT_MAX_DELTA_PER_DRAIN (100000000UL)  /* 1e8 ops/drain */

/*
 * Per-slot cross-drain state, owned by the parent's drain.
 *
 * prev -- last accepted lossless_op_count.  Starts at 0, and the delta
 *   guard is unconditional from the first drain: lossless_op_count is
 *   monotonic from 0 and one drain interval cannot legitimately produce
 *   more than LOSSLESS_OP_COUNT_MAX_DELTA_PER_DRAIN ops, so a first
 *   reading above that is rejected rather than taken as the baseline.
 *
 * untrusted -- the latest reading failed the guard.  Latches the
 *   one-shot diagnostic for the run and clears when a reading passes
 *   again.  Nothing clears it after an upward or over-ceiling scribble:
 *   the counter lives in the child's ring page, stats_ring_init() does
 *   not clear it on respawn, and prev stays anchored to the last good
 *   value, so such a slot stays untrusted for the rest of the run and
 *   only ever contributes its frozen prev.
 */
struct opclock_slot {
	unsigned long prev;
	bool untrusted;
};

enum opclock_verdict {
	OPCLOCK_ACCEPTED,
	OPCLOCK_REJECTED,		/* implausible, already reported this run */
	OPCLOCK_NEWLY_REJECTED,		/* implausible, first reading of a run */
};

/*
 * Fold one drain's reading of a slot's lossless_op_count.  Afterwards
 * the slot contributes s->prev to the fleet sum: the reading itself
 * when it passes both guards, else the last accepted value.  A rejected
 * reading does NOT update prev: keeping the last known-good baseline
 * keeps the delta check anchored.  A backward jump (raw < prev) is
 * rejected too; it violates the monotonic invariant and only a stomp of
 * shm can cause it.
 */
static inline enum opclock_verdict opclock_slot_observe(struct opclock_slot *s,
							 unsigned long raw)
{
	if (raw > LOSSLESS_OP_COUNT_SANE_CEILING || raw < s->prev ||
	    raw - s->prev > LOSSLESS_OP_COUNT_MAX_DELTA_PER_DRAIN) {
		if (s->untrusted)
			return OPCLOCK_REJECTED;
		s->untrusted = true;
		return OPCLOCK_NEWLY_REJECTED;
	}
	s->untrusted = false;
	s->prev = raw;
	return OPCLOCK_ACCEPTED;
}
