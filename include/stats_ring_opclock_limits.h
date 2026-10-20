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
 * A slot contributes the sum of the drain-to-drain deltas the guard
 * accepted, which equals the raw counter until something scribbles it.
 * A scribbled value never enters the fleet sum, only increments after
 * it do.
 *
 * LOSSLESS_OP_COUNT_SANE_CEILING (absolute): a reading above 2^52
 * (~4.5e15) is wild garbage, such as the observed 0x693bb2ae5ba348af
 * (~2^62.7); 2^52 is many orders of magnitude above any realistic run
 * total (100k ops/sec/child × years < 10^13).  It only labels the
 * diagnostic: the delta guard is what rejects a jump to such a value,
 * and a slot rebased onto one contributes only deltas from it.
 *
 * LOSSLESS_OP_COUNT_MAX_DELTA_PER_DRAIN (delta): lossless_op_count is
 * run-monotonic (never reset across child respawns).  A drain-to-drain
 * increment larger than this constant is implausible regardless of the
 * absolute value, which catches garbage at any magnitude.  Drains run
 * every main-loop tick, 25 ms when idle and back to back when busy, so
 * 1e8 per drain leaves a wide margin over the fastest realistic child
 * (1M syscalls/sec) even across a stalled tick.
 *
 * LOSSLESS_OP_COUNT_REBASE_SPAN_MS / _REBASE_MAX_PER_MS (rebase): a
 * rejected slot is trusted again once its readings have climbed
 * monotonically for at least REBASE_SPAN_MS of wall time, averaging no
 * more than REBASE_MAX_PER_MS -- once the counter behaves like an op
 * counter again.  Timing the climb rather than counting drains keeps
 * the test independent of the tick rate.  10,000 per ms (1e7/s) is ten
 * times the fastest realistic child and a hundredth of a nanosecond
 * clock, so a slot never rebases onto one at any cadence; and since a
 * nanosecond clock moves more than MAX_DELTA_PER_DRAIN in
 * REBASE_SPAN_MS, a clock written less often than that is rejected
 * again at its next write.  A microsecond or coarser clock, or any
 * slowly rising garbage, is indistinguishable from ops.  Ops counted
 * during the climb are dropped.
 *
 * LOSSLESS_OP_COUNT_MAX_REBASES: a slot can rebase this many times per
 * run.  After that it is only trusted again if its counter comes back
 * within MAX_DELTA_PER_DRAIN of where it was, so a periodic scribbler
 * cannot keep feeding the sum.
 *
 * A rejection emits a one-shot diagnostic (rate-limited to once per
 * implausible run via opclock_slot.untrusted, so
 * lossless_slot_implausible counts implausible runs, not the
 * slot × drain re-observation product).
 *
 * This header depends only on <stdbool.h> and may be included from
 * standalone test files that do not pull in the full stats_ring.h
 * include graph.
 */
#define LOSSLESS_OP_COUNT_SANE_CEILING        (1UL << 52)
#define LOSSLESS_OP_COUNT_MAX_DELTA_PER_DRAIN (100000000UL)  /* 1e8 ops/drain */
#define LOSSLESS_OP_COUNT_REBASE_SPAN_MS      250UL
#define LOSSLESS_OP_COUNT_REBASE_MAX_PER_MS   10000UL        /* 1e7 ops/s */
#define LOSSLESS_OP_COUNT_MAX_REBASES         4U

/*
 * Per-slot cross-drain state, owned by the parent's drain.
 *
 * prev -- the reading the last accepted delta ended at, or the reading
 *   the slot last rebased on.  Starts at 0, and the delta guard is
 *   unconditional from the first drain: lossless_op_count is monotonic
 *   from 0 and one drain interval cannot legitimately produce more than
 *   LOSSLESS_OP_COUNT_MAX_DELTA_PER_DRAIN ops, so a first reading above
 *   that is rejected rather than taken as the baseline.
 *
 * contrib -- what the slot adds to the fleet sum: every accepted delta.
 *   Frozen while the slot is untrusted.
 *
 * untrusted -- a reading failed the guard and the slot has been neither
 *   back in range nor rebased since.  Latches the one-shot diagnostic.
 *
 * climb_start, climb_start_ms, climb_last -- while untrusted: the
 *   reading and time the current monotonic climb began at, and its
 *   latest reading.
 *
 * rebases -- how many times the slot has rebased this run.
 */
struct opclock_slot {
	unsigned long prev;
	unsigned long contrib;
	unsigned long climb_start;
	unsigned long climb_start_ms;
	unsigned long climb_last;
	unsigned int rebases;
	bool untrusted;
};

enum opclock_verdict {
	OPCLOCK_ACCEPTED,		/* counted: the delta from prev */
	OPCLOCK_REJECTED,		/* not counted: the slot is still untrusted */
	OPCLOCK_NEWLY_REJECTED,		/* not counted: first reading of a run */
	OPCLOCK_REBASED,		/* not counted: trusted from this reading on */
};

/*
 * Fold one drain's reading of a slot's lossless_op_count, taken at
 * now_ms on CLOCK_MONOTONIC, and return what the slot contributes to
 * the fleet sum.  A reading within MAX_DELTA_PER_DRAIN above prev is
 * counted, whether the slot was trusted or its counter has come back
 * into range.  Anything else -- a jump, or a backward step, which
 * violates the monotonic invariant and only a stomp of shm can cause --
 * leaves prev and contrib alone, so the delta check stays anchored and
 * the slot's contribution never goes backwards.  An untrusted slot
 * rebases on the reading that completes a REBASE_SPAN_MS climb at no
 * more than REBASE_MAX_PER_MS, up to MAX_REBASES times; deltas count
 * again from the next drain.
 */
static inline unsigned long opclock_slot_observe(struct opclock_slot *s,
						 unsigned long raw,
						 unsigned long now_ms,
						 enum opclock_verdict *verdict)
{
	unsigned long elapsed;

	if (raw >= s->prev &&
	    raw - s->prev <= LOSSLESS_OP_COUNT_MAX_DELTA_PER_DRAIN) {
		s->contrib += raw - s->prev;
		s->prev = raw;
		s->untrusted = false;
		*verdict = OPCLOCK_ACCEPTED;
		return s->contrib;
	}

	*verdict = s->untrusted ? OPCLOCK_REJECTED : OPCLOCK_NEWLY_REJECTED;
	if (!s->untrusted || raw < s->climb_last) {
		s->untrusted = true;
		s->climb_start = raw;
		s->climb_start_ms = now_ms;
		s->climb_last = raw;
		return s->contrib;
	}
	s->climb_last = raw;

	elapsed = now_ms >= s->climb_start_ms ? now_ms - s->climb_start_ms : 0;
	if (elapsed < LOSSLESS_OP_COUNT_REBASE_SPAN_MS)
		return s->contrib;
	if (raw - s->climb_start > LOSSLESS_OP_COUNT_REBASE_MAX_PER_MS * elapsed) {
		s->climb_start = raw;
		s->climb_start_ms = now_ms;
		return s->contrib;
	}
	if (s->rebases >= LOSSLESS_OP_COUNT_MAX_REBASES)
		return s->contrib;

	s->rebases++;
	s->prev = raw;
	s->untrusted = false;
	*verdict = OPCLOCK_REBASED;
	return s->contrib;
}
