#pragma once

#include <sys/types.h>

#include "locks.h"
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
 * Reset every CMP_HINTS_BLOOM_RESET cmp_hints_collect() calls (a fixed
 * cadence per child; trades stale-skip risk against contention savings).
 * Per-child storage so the check needs no cross-process atomic.
 */
#define CMP_HINTS_BLOOM_BITS	8192
#define CMP_HINTS_BLOOM_BYTES	(CMP_HINTS_BLOOM_BITS / 8)
#define CMP_HINTS_BLOOM_MASK	(CMP_HINTS_BLOOM_BITS - 1)
#define CMP_HINTS_BLOOM_RESET	4096U

struct cmp_hints_bloom {
	uint8_t bits[CMP_HINTS_BLOOM_BYTES];
	unsigned int calls;	/* cmp_hints_collect() calls since last reset */
};

struct cmp_hint_entry {
	unsigned long value;
	unsigned long cmp_ip;
	uint32_t size;		/* operand width in bytes: 1, 2, 4, or 8 */
	uint32_t last_used;	/* pool->generation snapshot at insertion */
};

struct cmp_hint_pool {
	lock_t lock;
	unsigned int count;
	/* Monotonic counter bumped under pool->lock on every insertion /
	 * duplicate-refresh.  The current value stamps the entry's
	 * last_used field; the entry with the lowest last_used is the LRU
	 * eviction victim when count == CMP_HINTS_PER_SYSCALL. */
	unsigned int generation;
	struct cmp_hint_entry entries[CMP_HINTS_PER_SYSCALL];
};

struct cmp_hints_shared {
	struct cmp_hint_pool pools[1024]; /* indexed by syscall number */
};

extern struct cmp_hints_shared *cmp_hints_shm;

/* Called once from init_shm() to allocate shared hint storage. */
void cmp_hints_init(void);

/* Extract comparison operands from a CMP-mode trace buffer and
 * add interesting constants to the hint pool for syscall nr. */
void cmp_hints_collect(unsigned long *trace_buf, unsigned int nr);

/* Try to extract a random hint value for the given syscall.
 * Returns true with the hint written to *out, or false if none available. */
bool cmp_hints_try_get(unsigned int nr, unsigned long *out);

/* Mid-run snapshot cadence for cmp_hints_maybe_snapshot().  CMP records
 * are expensive to collect -- each one requires a kernel-side comparison
 * to fire on a syscall-derived input -- so the pool grows slowly and the
 * triggers are slacker than the kcov bitmap's: 200 newly-added entries
 * across all pools OR 600s since the last save, whichever comes first.
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
