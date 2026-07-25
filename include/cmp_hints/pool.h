#pragma once

#include <sys/types.h>

#include "locks.h"

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

struct cmp_hint_entry {
	unsigned long value;
	unsigned long cmp_ip;
	uint32_t size;		/* operand width in bytes: 1, 2, 4, or 8 */
	/*
	 * SHADOW per-entry feedback scoring for the score-based feedback
	 * loop.
	 *
	 * On a successful cmp_hints_try_get_ex(), the (nr, arch, cmp_ip,
	 * value, size, transform) tuple is stashed per-child.  On dispatch
	 * completion the stash is drained: a PC-edge win in PC-mode bumps
	 * wins on the matching pool entry; a no-win bumps misses; CMP-mode
	 * novelty is credited to a SEPARATE flat counter (kept out of the
	 * per-entry score so CMP novelty cannot masquerade as PC-edge
	 * conversion -- measurement-first discipline).  These per-entry
	 * counters are SHADOW only and do not steer pool selection; a
	 * future live-pick path will weigh entries by them.
	 *
	 * Saturating uint16_t (cap 65535) is enough headroom for the
	 * shadow window: a per-entry score that high already conclusively
	 * dominates / loses against unscored peers.  Replaces the 4-byte
	 * pad slot so cmp_hint_entry stays at 32 bytes -- both the
	 * per-syscall pools[] grid and the field_pools[] table inherit the
	 * counters for free without re-laying-out either fixed array.
	 *
	 * Updated lock-free under the same RELAXED atomic discipline as
	 * the pool's count load: a concurrent eviction on the matching
	 * slot may misattribute a single ++ to the replacement entry, which
	 * is acceptable for shadow scoring (advisory, no correctness use).
	 */
	uint16_t wins;
	uint16_t misses;
	uint64_t last_used;	/* pool->last_used_stamp at insertion */
};

/* Magic word flanking pool->entries[] for wild-write detection.  Init-
 * time written into canary_pre and canary_post by cmp_hints_init() and
 * never touched after; a delta is read-only evidence that a kernel-side
 * stomp (via a syscall arg pointer aliasing into the SHM) reached the
 * pool.  Value is an arbitrary non-pattern u64 unlikely to be produced
 * by either zero-init or any normal kernel write the fuzzer drives. */
#define CMP_HINTS_POOL_CANARY	0x7c4d0b3f9e2a5168ULL

/*
 * SHADOW zero-PC-win hard-cool budget threshold.
 *
 * A recent per-syscall pool observation showed ~9k old-flat-pool hints
 * credited with zero PC-edge wins across a fuzz window: the pool kept
 * serving hints that never converted.  There is no cooling policy today
 * that would retire such a dead pool -- the by-pool shadow at credit.c
 * partitions PC outcomes by pool_kind but does not quantify what a
 * hard-cool would save.
 *
 * zero_win_streak on struct cmp_hint_pool is the per-pool state a
 * hypothetical hard-cool would key off: consecutive PC-outcome MISS
 * credits with no intervening PC-WIN, bumped from the per-syscall arm of
 * cmp_hints_feedback_credit_pc().  When the streak crosses this budget
 * the shadow counters in kcov_shm (cmp_hint_pool_zero_win_would_retire /
 * cmp_hint_pool_zero_win_would_save) bump the "N pools retired / M
 * injections saved at budget T" pair the follow-up live cool switchover
 * needs to size the trade-off.  Live behaviour is unchanged; the pool is
 * NOT actually cooled, this is a measurement-only shadow.
 *
 * T=64 is 4x CMP_HINTS_PER_SYSCALL (16) -- roughly one full pool worth
 * of consecutive-miss evidence per retirement decision, aggressive
 * enough to fire inside a windowed observability tick on a dead pool
 * but not so twitchy that a run of unlucky misses on a live pool trips
 * it.  A future live switchover will tune this against the shadow's
 * reported saved:retired ratio.
 */
#define CMP_HINT_ZERO_WIN_BUDGET_T	64U

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
	 * cmp_hints_save_file: a dedup-refresh only updates last_used and
	 * leaves the set of tuples in the pool unchanged, so it must not
	 * advance the sum and must not force a snapshot save (the bytes
	 * serialised to disk, modulo last_used timestamps, are identical).
	 * last_used_stamp below carries the LRU-clock role. */
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
	/* SHADOW consecutive zero-PC-win injection streak.  Bumped
	 * atomically from cmp_hints_feedback_credit_pc()'s per-syscall
	 * arm on every PC-outcome MISS credit that landed on this pool,
	 * reset on the first PC-outcome WIN credit.  Feeds the hard-cool
	 * shadow at CMP_HINT_ZERO_WIN_BUDGET_T -- the counter is peeked
	 * per credit to bump kcov_shm->cmp_hint_pool_zero_win_would_*.
	 * Advisory / measurement only: live pool selection ignores it and
	 * a torn observation across concurrent child credits at worst
	 * misplaces a single retire/save bump.  RELAXED atomic discipline
	 * matches the rest of the by-pool shadow. */
	uint32_t zero_win_streak;
};

/*
 * Run-local "recent" tier.
 *
 * The durable per-syscall pool above caps at CMP_HINTS_PER_SYSCALL
 * (16) entries and saturates on long fuzz runs: cmp_hints_save_reject_cap
 * dominates cmp_hints_unique_inserts, so the late-run constants the
 * kernel produced never reach the consumer because the LRU floor is
 * already full of older entries that keep refreshing their last_used
 * stamps.  The recent ring is a small second tier that absorbs every
 * fresh pool_add_locked() insert into a per-syscall circular buffer,
 * never persisted, never weighted against the durable pool's LRU --
 * just a window over what the kernel CMP'd recently.
 *
 * Eight entries per (nr, arch) is enough to give the recent-first arm
 * a meaningful population without competing with the durable pool's
 * memory footprint: MAX_NR_SYSCALL * 2 * CMP_RECENT_PER_SYSCALL *
 * sizeof(cmp_recent_entry) is on the order of a few hundred KiB,
 * matching the existing pool grid's scale.  Entries are written under
 * the durable pool's lock (the only writer is cmp_hints_flush_pending,
 * already holding it for the durable insert that triggers the recent
 * insert), and read lock-free from cmp_hints_try_get_ex the same way
 * the durable pool is -- naturally aligned fields, advisory values,
 * torn cross-field reads tolerated.
 *
 * head is the next slot to write; count grows up to
 * CMP_RECENT_PER_SYSCALL and then sticks at the cap (the ring stays
 * full once it has saturated).  Inserts overwrite the slot at head
 * and advance head modulo the cap, so the oldest entry is always the
 * one displaced.  No dedup -- the ring deliberately accepts the same
 * (cmp_ip, value, size) tuple again if the kernel saw it again, so
 * "recent" semantics aren't diluted by deduping against an earlier
 * window.
 */
#define CMP_RECENT_PER_SYSCALL 8

struct cmp_recent_entry {
	unsigned long value;
	unsigned long cmp_ip;
	uint32_t size;		/* operand width in bytes: 1, 2, 4, or 8 */
	uint32_t pad;
};

struct cmp_recent_pool {
	unsigned int head;
	unsigned int count;
	struct cmp_recent_entry entries[CMP_RECENT_PER_SYSCALL];
};
