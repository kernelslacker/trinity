#pragma once

#include <sys/types.h>

#include "locks.h"
#include "syscall.h"
#include "types.h"

/*
 * KCOV comparison operand hint pool.
 *
 * When running in KCOV_TRACE_CMP mode, the kernel records every
 * comparison instruction with its operands. We extract constants
 * the kernel compares against and store them per-syscall-number.
 * During argument generation, we sometimes substitute a learned
 * constant instead of a random value, dramatically improving the
 * fuzzer's ability to pass kernel validation checks.
 *
 * Entries are keyed by (cmp_ip, value, size) -- a single comparison
 * site that exercises both small and large operand widths is two
 * distinct hints, and the same constant compared at two different
 * kernel PCs is two distinct hints.  Precision over robustness: a
 * kernel rebuild that shuffles addresses invalidates the IP keys,
 * but the kallsyms fingerprint on the persisted file catches that
 * and forces a cold start.
 */

/* Max unique hints stored per syscall number.  Halved from the original
 * 32 once the per-child seen-bloom (below) absorbed the dedup-refresh
 * volume: with the bloom short-circuiting most refresh hits before they
 * touch the pool, the eviction loop runs more often on real "least
 * useful" entries instead of "least recently dedup-refreshed", so a
 * smaller pool retains its useful tail without needing the 32-slot
 * cushion.  Halves the per-syscall pool_add_locked linear-scan cost
 * (insert + eviction) and the per-syscall struct size, dropping the
 * fleet-wide hint cap from MAX_NR_SYSCALL * 32 to MAX_NR_SYSCALL * 16. */
#define CMP_HINTS_PER_SYSCALL 16

/*
 * Per-child seen-bloom over (cmp_ip, value, size) tuples.  Consulted in
 * cmp_hints_collect() before the per-pool lock + linear-scan dedup so a
 * tuple this child has already pushed into the pool within the recent
 * window skips the pool_add_locked() round-trip entirely.  Pure cache:
 * a false positive just means the LRU stamp on a real pool entry is not
 * refreshed (the entry may evict sooner), never a correctness bug --
 * cmp_hints are advisory.  Bloom misses still call pool_add_locked()
 * because the bloom never lies about novelty in the other direction.
 *
 * Sized 8192 bits (1 KiB) per child with k=2 hashes -- the textbook
 * efficient point for FPR well under 10% at the few-hundred-unique-
 * tuples-per-window load the dedup-refresh path sees in practice.
 * Reset every CMP_HINTS_BLOOM_RESET CMP records consumed (a
 * record-driven cadence per child; this tracks the actual rate
 * bits land in the bloom and stops single high-record calls
 * from saturating the filter early).
 * Per-child storage so the check needs no cross-process atomic.
 */
#define CMP_HINTS_BLOOM_BITS	8192
#define CMP_HINTS_BLOOM_BYTES	(CMP_HINTS_BLOOM_BITS / 8)
#define CMP_HINTS_BLOOM_MASK	(CMP_HINTS_BLOOM_BITS - 1)
#define CMP_HINTS_BLOOM_RESET	4096U

struct cmp_hints_bloom {
	uint8_t bits[CMP_HINTS_BLOOM_BYTES];
	unsigned int records;	/* CMP records consumed since last reset */
};

/*
 * Per-call attribution scratch for the greedy CMP RedQueen re-exec.
 * cmp_hints_collect() scans each CMP record's arg1 (the
 * compile-time constant the kernel compared against) against the
 * dispatching syscall's rec->a1..aN.  On match it stamps (slot, cmp_ip,
 * value, size) here; the dispatch_step tail drains the buffer and re-runs
 * the syscall with the targeted slot pinned to the captured constant.
 *
 * Sized 8 entries (24 B each, ~192 B per child) so a single dispatch
 * can stage multiple attributions without truncation; the per-call
 * re-exec cap keeps actual drain to one per parent dispatch
 * in the initial deployment.  Reset every dispatch_step tail (drain +
 * count = 0) so attribution buffers do NOT carry forward across calls.
 *
 * "slot" is a 1-based arg index (1..6) matching the rec->aN naming
 * convention.  cmp_ip / value / size mirror the (ip, val, size) tuple
 * the existing pool entry uses.
 */
#define MAX_REEXEC_PENDING	8U

struct reexec_pending {
	unsigned long cmp_ip;
	unsigned long value;
	unsigned int size;
	unsigned int slot;
};

/*
 * Baseline re-exec gate denominator: ONE_IN(N) gate at the dispatch_step
 * tail outside plateau windows; inside a plateau classified as
 * CMP_RISING_PC_FLAT the gate switches to always-on (the intensification
 * arm).  4 == 25% baseline rate; the
 * realised per-CMP-child overhead is attribution_rate * 0.25 syscalls,
 * with the CMP-mode pool being roughly --cmp-fraction of the fleet, so
 * fleet-wide steady-state cost is well within noise.
 */
#define REDQUEEN_REEXEC_GATE_DENOM	4

/*
 * Per-window cap on re-exec dispatches.  Bounds runaway when a
 * hot attributing syscall accumulates a stream of matches: per-child
 * re-exec count is reset every REDQUEEN_REEXEC_WINDOW_OPS child
 * iterations and capped at REDQUEEN_REEXEC_WINDOW_CAP within the
 * window.  Exceedance bumps kcov_shm->reexec_window_cap_hit and skips
 * further re-execs until the next window roll.
 *
 * Sized off STRATEGY_WINDOW so the cap is conceptually "no more than
 * 25% of the bandit's rotation budget" -- matches the same headroom
 * fraction the baseline re-exec gate targets.
 */
#define REDQUEEN_REEXEC_WINDOW_OPS	(1UL << 17)	/* mirror STRATEGY_WINDOW */
#define REDQUEEN_REEXEC_WINDOW_CAP	(REDQUEEN_REEXEC_WINDOW_OPS / 4)

struct cmp_hint_entry {
	unsigned long value;
	unsigned long cmp_ip;
	uint32_t size;		/* operand width in bytes: 1, 2, 4, or 8 */
	uint32_t pad;
	uint64_t last_used;	/* pool->last_used_stamp at insertion */
};

/* Magic word flanking pool->entries[] for wild-write detection.  Init-
 * time written into canary_pre and canary_post by cmp_hints_init() and
 * never touched after; a delta is read-only evidence that a kernel-side
 * stomp (via a syscall arg pointer aliasing into the SHM) reached the
 * pool.  Value is an arbitrary non-pattern u64 unlikely to be produced
 * by either zero-init or any normal kernel write the fuzzer drives. */
#define CMP_HINTS_POOL_CANARY	0x7c4d0b3f9e2a5168ULL

struct cmp_hint_pool {
	lock_t lock;
	/* Header-side wild-write sentinel, placed between lock and count
	 * so a stomp that overshoots the 24-byte lock_t or undershoots
	 * the count field by a few bytes lands in the canary instead of
	 * silently corrupting count or generation.  A stomp landing
	 * exactly on count (4 bytes at offset 32 within the pool) is
	 * still invisible here -- only cmp_hints_count_oob catches that
	 * direct hit -- but wider writes that bracket the count field
	 * trip this slot.  Lock-word corruption itself is already caught
	 * by the LOCK_RESERVED_DIRTY check on the next acquire; this
	 * canary covers the gap between those two existing signals. */
	uint64_t canary_lock_post;
	unsigned int count;
	/* Monotonic counter bumped under pool->lock only when pool content
	 * actually changes -- a fresh insert or an evict-replace, never on a
	 * dedup-refresh hit.  Summed across all MAX_NR_SYSCALL pools by
	 * cmp_hints_total_generation() to gate the snapshot dirty-bit in
	 * cmp_hints_save_file; bumping it on dedup-refresh used to defeat
	 * that gate by advancing the sum every time a hot tuple re-touched
	 * its last_used field, even though the bytes serialised to disk
	 * (modulo the last_used timestamps themselves) were identical.
	 * last_used_stamp below carries the LRU-clock role generation used
	 * to play. */
	unsigned int generation;
	/* Per-pool monotonic LRU clock, bumped under pool->lock on every
	 * pool_add_locked call (including dedup-refresh hits).  The current
	 * value stamps the entry's last_used field; the entry with the
	 * smallest last_used is the eviction victim when count ==
	 * CMP_HINTS_PER_SYSCALL.  Deliberately NOT included in the
	 * snapshot-dirty-bit (cmp_hints_total_generation): dedup-refresh
	 * advances this clock to keep an actively-observed tuple from
	 * being evicted, but does not change which tuples live in the
	 * pool, so it should not force a snapshot save.
	 *
	 * Widened to uint64_t after audit (2026-05-26) so a multi-day
	 * fuzz run can't wrap the 32-bit counter and invert the LRU
	 * eviction order once the stamp space rolls past UINT_MAX. */
	uint64_t last_used_stamp;
	uint64_t canary_pre;
	struct cmp_hint_entry entries[CMP_HINTS_PER_SYSCALL];
	uint64_t canary_post;
	/* Sticky one-shot flag latched by cmp_hints_pool_corrupted() on
	 * first detection of a wild-write into this pool (either count
	 * out-of-cap or canary stomp).  Subsequent reader calls observe
	 * the flag and short-circuit without re-bumping the kcov_shm
	 * counters; without this, cmp_hints_flush_pending's batch loop
	 * would multiply a single corruption event by up to
	 * CMP_HINTS_PENDING_BATCH bumps per cmp_hints_collect call.
	 * Never cleared: a stomped pool stays quarantined for the
	 * lifetime of the trinity invocation. */
	bool corrupted;
};

/*
 * Pool grid indexed by [syscall_nr][do32 ? 1 : 0].  Mirrors the arch
 * dimension already carried by cmp_hints_strip[2][MAX_NR_SYSCALL]:
 * under biarch, syscall nr=N under the 32-bit table and syscall nr=N
 * under the 64-bit table are unrelated calls, so a single per-nr slot
 * would have them contend for the 16-entry dedup table and bloom and
 * silently evict each other's constants.  Uniarch builds only ever
 * touch the [*][0] column; the unused [*][1] half is a few hundred
 * KiB of shm that mirrors the strip-table's identical waste.
 */
struct cmp_hints_shared {
	struct cmp_hint_pool pools[MAX_NR_SYSCALL][2];
	/* Parent-tick scan accelerator; incremented before pool->lock acquire,
	 * decremented after release.  check_all_locks may skip the family when
	 * zero. */
	unsigned long held_count;
};
_Static_assert(MAX_NR_SYSCALL == 1024,
	"cmp_hints_shared layout assumes MAX_NR_SYSCALL == 1024");

extern struct cmp_hints_shared *cmp_hints_shm;

/* Called once from init_shm() to allocate shared hint storage. */
void cmp_hints_init(void);

/* Extract comparison operands from a CMP-mode trace buffer and
 * add interesting constants to the hint pool for syscall nr. */
void cmp_hints_collect(unsigned long *trace_buf, unsigned int nr, bool do32);

/* Try to extract a random hint value for the given syscall.
 * Returns true with the hint written to *out, or false if none available.
 * do32 selects between the 64-bit and 32-bit syscall-table pools so
 * biarch builds do not contend for the same per-nr dedup slots. */
bool cmp_hints_try_get(unsigned int nr, bool do32, unsigned long *out);

/* Advance the chaos-mode window counter.  Called once per bandit window
 * rotation from maybe_rotate_strategy().  Every CHAOS_WINDOW_MODULO'th
 * window flips cmp_hints_chaos_active to true for the duration of that
 * window so cmp_hints_try_get returns false and the caller falls
 * through to its random-arg path -- the cmp-hints pool saturates on
 * kernel-validated constants, which biases generated args AWAY from
 * the invalid-combination space most WARN_ONs guard.  Periodic
 * suppression gives random generation a fair shot at that space.
 *
 * cmp_hints_chaos_query exposes the current toggle for diagnostics
 * (the stats block prints it alongside the chaos_suppressed counter).
 * Hot-path callers should NOT consult it -- cmp_hints_try_get already
 * gates internally. */
void cmp_hints_chaos_tick(void);
bool cmp_hints_chaos_query(void);

/* Read pool->count clamped to the CMP_HINTS_PER_SYSCALL cap.  Returns 0
 * if the pool has been corrupted by a wild kernel-side write (latched
 * via the same gate as cmp_hints_try_get).  Use from callers that need
 * the count for accounting/heuristics but do not index into entries[];
 * the alternative -- a raw read of pool->count -- silently folds the
 * stomped sentinel value (often in the millions) into running totals
 * and trips downstream classifiers on a non-existent pool population. */
unsigned int cmp_hints_pool_safe_count(struct cmp_hint_pool *pool);

/* Mid-run snapshot cadence for cmp_hints_maybe_snapshot().  CMP records
 * are expensive to collect -- each one requires a kernel-side comparison
 * to fire on a syscall-derived input -- so the pool grows slowly and the
 * triggers are slacker than the kcov bitmap's: snapshots fire only when
 * BOTH 200 newly-added entries have accumulated across all pools AND
 * 600s have elapsed since the last save.  Either gate alone is
 * insufficient -- the generation gate would still over-fire during the
 * initial fill phase before pools saturate, and the time gate alone
 * would write near-identical payloads on a long-since-saturated pool.
 * Hardcoded -- no operator knob, fleet boxes shouldn't need to retune. */
#define CMP_HINTS_SNAPSHOT_NEW			200UL
#define CMP_HINTS_SNAPSHOT_INTERVAL_SEC		600UL

/* Warm-start persistence for the cmp-hints pool.  Entries are keyed by
 * (cmp_ip, value, size) so the on-disk file is only meaningful against
 * the same kernel binary that produced it; the kallsyms-sha256 in the
 * header (same fingerprint algorithm the kcov bitmap uses, via
 * kcov_get_kernel_fp) catches rebuilds and forces a cold start.  Stale
 * or unreadable files are silently discarded and the loader returns
 * false; cold-start is the legitimate first-run state. */
bool cmp_hints_save_file(const char *path);
bool cmp_hints_load_file(const char *path);
const char *cmp_hints_default_path(void);

/* Wire periodic mid-run snapshots of the cmp-hints pool to PATH.
 * Subsequent cmp_hints_maybe_snapshot() calls become live; a no-op
 * before this is called.  Path is copied. */
void cmp_hints_enable_snapshots(const char *path);

/* Cheap per-tick gate: writes the snapshot if either trigger has elapsed
 * since the last successful save, otherwise returns immediately.  Called
 * from the parent's stats tick alongside the kcov-bitmap snapshot. */
void cmp_hints_maybe_snapshot(void);

/* Total number of on-disk entries rejected by cmp_hints_load_file()
 * across the most recent (and only) load attempt.  Diagnostic counter;
 * a non-zero value means the file produced by a prior run contained
 * slots that failed the bounds / size / IP-range validation in the
 * loader and were skipped while the surrounding pool was kept. */
extern unsigned long cmp_hints_load_rejected_entries;
