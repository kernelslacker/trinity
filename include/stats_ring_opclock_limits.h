#pragma once

/*
 * Plausibility guard thresholds for the per-child lossless op counter
 * (stats_ring.lossless_op_count).  Canonical home for both constants so
 * the production drain (stats/stats-ring.c) and the invariant self-test
 * (tests/stats_opclock_lossless_test.c) share the same tokens without
 * copying the literals or maintaining a "keep in sync" comment.
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
 * diagnostic (rate-limited to once per slot via slot_implausible_reported
 * so lossless_slot_implausible counts distinct corrupted slots, not the
 * slot × drain re-observation product).
 *
 * This header has no dependencies beyond the C preprocessor and may be
 * included from standalone test files that do not pull in the full
 * stats_ring.h include graph.
 */
#define LOSSLESS_OP_COUNT_SANE_CEILING        (1UL << 52)
#define LOSSLESS_OP_COUNT_MAX_DELTA_PER_DRAIN (100000000UL)  /* 1e8 ops/drain */
