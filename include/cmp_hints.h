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
 * Sized 8 entries (32 B each, ~256 B per child) so a single dispatch
 * can stage multiple attributions without truncation; the per-call
 * re-exec cap keeps actual drain to one per parent dispatch
 * in the initial deployment.  Reset every dispatch_step tail (drain +
 * count = 0) so attribution buffers do NOT carry forward across calls.
 *
 * "slot" is a 1-based arg index (1..6) matching the rec->aN naming
 * convention.  cmp_ip / value / size mirror the (ip, val, size) tuple
 * the existing pool entry uses; cmp_ip is the canonical (KASLR-stripped)
 * comparison-instruction address, the same value cmp_hints_collect()
 * routes into the bloom and the per-syscall pool.
 *
 * field_kind selects how the consumer applies the pin for the
 * field-scoped pool.
 * REEXEC_FIELD_NONE is the scalar-slot pin: the consumer splices `value`
 * into rec->a<slot>'s low `size` bytes and preserves its high bits (a
 * full or unknown width overwrites the whole slot outright).  The field
 * kinds instead treat rec->a<slot> as a pointer to a fixed-size struct
 * and pin ONE field
 * inside the freshly regenerated buffer, leaving the rest of the
 * generated struct intact -- so a kernel comparison that fired on a
 * single struct field is satisfied without spraying the constant across
 * the whole arg.  The scalar attribution scan runs first and stays
 * byte-for-byte unchanged; a field scan only runs after the scalar +
 * width passes miss, and only on syscalls that actually carry a
 * field-eligible arg, so scalar RedQueen stays cheap.  Today only the
 * ARG_TIMESPEC fixed-layout tv_sec/tv_nsec pair is wired; the xattr
 * namespace vocab and the variable-length / nested buffers land in the
 * follow-up alongside the field-scoped CMP pool.
 */
#define MAX_REEXEC_PENDING	8U

enum reexec_field_kind {
	REEXEC_FIELD_NONE = 0,		/* scalar slot pin (historical) */
	REEXEC_FIELD_TIMESPEC_SEC,	/* pin ((struct timespec *)slot)->tv_sec */
	REEXEC_FIELD_TIMESPEC_NSEC,	/* pin ((struct timespec *)slot)->tv_nsec */
};

struct reexec_pending {
	unsigned long cmp_ip;
	unsigned long value;
	unsigned int size;
	unsigned int slot;
	enum reexec_field_kind field_kind;
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

/*
 * Per-call burst-drain cap for the CMP_RISING_PC_FLAT plateau A/B measure
 * arm.  When plateau_burst && child->burst_drain_arm_b, the dispatch_step
 * tail caps the per-call drain at this many reexec_pending[] entries and
 * breaks the loop on a helper FAIL (the per-window ceiling hit); the
 * control arm (burst_drain_arm_b == false) is unaffected and continues to
 * drain up to MAX_REEXEC_PENDING per the greedy baseline landed in
 * b86f2e77a846 ("drain all staged reexec_pending entries per dispatch").
 * K=4 is half the producer-side buffer cap: the measurement asks whether
 * a surgical top-K drain converts to more distinct-edge lift per attempt
 * than the greedy drain during the exact plateau where the greedy drain
 * has the most fuel to burn.
 */
#define REDQUEEN_REEXEC_BURST_DRAIN	4U

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
 * Field-scoped attribution pool (narrow MVP).
 *
 * The per-syscall pools above ([nr][do32]) attribute a kernel CMP
 * constant to a *syscall slot* but not to a specific struct field --
 * so a value the kernel compared against, say, clone_args::flags is
 * sprayed back into any broad scalar slot of the same syscall rather
 * than steered to the matching field of the same cataloged struct.
 * Field pools are keyed by (nr, do32, arg_idx, desc, field_idx, size)
 * so a future consumer side can re-inject the constant at the exact
 * field that produced it; this header only carries the recording-path
 * storage.
 *
 * Storage is a fixed-size open-addressed table.  A bounded probe length
 * keeps lookup O(1); probe exhaustion drops the record (advisory pool,
 * no correctness impact) and bumps cmp_field_attribution_pool_full so
 * a saturated table is directly observable in stats.  Buckets are
 * claimed lazily on the first matching record by RELEASE-storing the
 * desc pointer (the occupancy gate); readers ACQUIRE-load desc before
 * reading the rest of the key so a partially-written key is invisible.
 *
 * check_all_locks() walks the per-syscall pools[][2] grid but does NOT
 * yet visit field_pools[].  A child dying while holding a field-pool
 * lock wedges that ONE bucket -- bounded blast radius; the rest of the
 * field table and every per-syscall pool keep working.  The walk will
 * extend once the consumer side (re-injection) lands.
 */
#define CMP_FIELD_POOL_BUCKETS		256U
#define CMP_FIELD_POOL_PROBE_MAX	8U
_Static_assert((CMP_FIELD_POOL_BUCKETS & (CMP_FIELD_POOL_BUCKETS - 1)) == 0,
	       "CMP_FIELD_POOL_BUCKETS must be a power of two");

struct struct_desc;	/* forward decl; full type in include/struct_catalog.h */

/*
 * Key tuple identifying one field pool.  desc doubles as the bucket
 * occupancy gate: NULL means the bucket is empty and may be claimed; a
 * non-NULL desc is published with RELEASE so a reader that ACQUIRE-loads
 * desc is guaranteed to see the rest of the key.
 */
struct cmp_field_pool_key {
	const struct struct_desc *desc;
	uint16_t nr;
	uint8_t do32;
	uint8_t arg_idx;	/* 1-based syscall arg index (1..6) */
	uint16_t field_idx;	/* index into the resolved fields[] array */
	uint8_t size;		/* CMP operand width in bytes: 1, 2, 4, or 8 */
	uint8_t pad;
};

struct cmp_field_pool {
	lock_t lock;
	uint64_t canary_lock_post;
	unsigned int count;
	unsigned int generation;
	uint64_t last_used_stamp;
	uint64_t canary_pre;
	struct cmp_hint_entry entries[CMP_HINTS_PER_SYSCALL];
	uint64_t canary_post;
	struct cmp_field_pool_key key;
	bool corrupted;
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

/*
 * SHADOW typed-CMP-hypothesis store.
 *
 * Layered on top of the raw cmp-hint pools above as a PARALLEL table:
 * the raw pools stay the canonical (cmp_ip, value, size) ledger and
 * the hypothesis store represents typed inferences built FROM those
 * observations.  Kept outside struct cmp_hint_entry deliberately so the
 * raw-hint lookup path stays cache-tight and so hypothesis layout churn
 * during the rewrite cannot perturb the recording-side fast path.
 *
 * Populated by cmp_hyp_observe() out of cmp_hints_flush_pending(); no
 * consumer reads the store and no injection path substitutes a
 * hypothesis-derived value -- the candidate-API + feedback wiring lands
 * in follow-up units.  Until then the live pick stays byte-for-byte
 * unchanged and every entry sits in CMP_HYP_STATE_OBSERVED.
 */
enum cmp_hypothesis_kind {
	CMP_HYP_EXACT,
	CMP_HYP_RANGE,
	CMP_HYP_BOUNDARY,
	CMP_HYP_BITMASK,
	CMP_HYP_ENUM_FAMILY,
	CMP_HYP_ALIGNMENT,
	CMP_HYP_LENGTH,
	CMP_HYP_FOREIGN_VALUE,
	CMP_HYP_KIND_NR,
};

enum cmp_hypothesis_state {
	CMP_HYP_STATE_OBSERVED,		/* inferred from observations, never injected */
	CMP_HYP_STATE_TESTING,		/* selected for injection / RedQueen re-exec */
	CMP_HYP_STATE_PROMOTED,		/* produced a PC-edge / transition / corpus win */
	CMP_HYP_STATE_DEMOTED,		/* repeatedly consumed without useful outcome */
	CMP_HYP_STATE_RETIRED,		/* stale, invalid, or superseded */
	CMP_HYP_STATE_NR,
};

/*
 * Demote miss threshold lives in cmp_hyp_credit_outcome()'s scoring
 * pass (`ms >= 8`).  Retirement is the dead-end after sustained noise:
 * a DEMOTED hypothesis that crosses 8x the demote threshold without
 * earning ANY win is RETIRED and removed from the picker pool.  Kept
 * here so the picker / dump code can reference the same constant. */
#define CMP_HYP_RETIRE_MISS_THRESHOLD	64U

/*
 * Reason partition for the LIVE typed-hypothesis inject path.  Each
 * value names a distinct site on the path from cmp_hyp_try_live_inject()
 * through the caller's accept-range gate.  The downstream reasons
 * (NO_MATCH, DERIVE_FAIL, ACCEPT_REJECT) and the head-gate failure
 * reasons (NOT_PLATEAU, DICE_MISS) bump on early-return; the channel
 * reasons (BOOTSTRAP, PROMOTED_BYPASS) bump on channel-fire SUCCESS to
 * expose which non-plateau channel admitted the call.  The sum across
 * head-gate failure reasons + (BOOTSTRAP + PROMOTED_BYPASS) +
 * (NO_MATCH + DERIVE_FAIL + ACCEPT_REJECT) + cmp_hyp_live_injected gives
 * the total typed-eligible invocations of the inject arm minus the
 * channel-A plateau opens that did not bump any channel counter (those
 * are visible as live_inject_gate_passed minus BOOTSTRAP minus
 * PROMOTED_BYPASS).
 *
 * NOT_PLATEAU/DICE_MISS now bump only when ALL channels fail to open:
 * NOT_PLATEAU when plateau was off (channels B and C both lost their
 * dice), DICE_MISS when plateau was on but channel A and the bypass
 * channels all lost.
 */
enum cmp_hyp_live_inject_reason {
	CMP_HYP_LIVE_INJECT_REASON_NOT_PLATEAU,	  /* plateau off AND all bypass channels lost their dice */
	CMP_HYP_LIVE_INJECT_REASON_DICE_MISS,	  /* plateau on AND every channel's dice lost */
	CMP_HYP_LIVE_INJECT_REASON_NO_MATCH,	  /* no qualifying hyp at (cmp_ip, width): picker NULL, or PROMOTED-only channel C contender at a site with no PROMOTED entry */
	CMP_HYP_LIVE_INJECT_REASON_DERIVE_FAIL,	  /* cmp_hyp_derive_value() bailed */
	CMP_HYP_LIVE_INJECT_REASON_ACCEPT_REJECT, /* caller's accept-range gate rejected derived value */
	CMP_HYP_LIVE_INJECT_REASON_BOOTSTRAP,	  /* channel B opened: bootstrap dice fired regardless of plateau */
	CMP_HYP_LIVE_INJECT_REASON_PROMOTED_BYPASS, /* channel C opened: PROMOTED hyp present and bypass dice fired */
	CMP_HYP_LIVE_INJECT_REASON_NR,
};

/*
 * RANGE-identity discriminators.  Carried per-entry on CMP_HYP_RANGE
 * hypotheses so dedup keys the entry by an inferred logical-probe
 * identity rather than by literal compare operands -- value churn at
 * any single comparison site, and multiple sites that observe the same
 * logical range, both collapse to ONE entry.  Zero for non-RANGE
 * kinds; their dedup keys are unchanged.
 *
 * KCOV records only operand values, NOT the compare OPERATOR, so
 * direction is INFERRED heuristically from the accumulated cluster
 * (exemplar position relative to lo/hi).  CMP_RANGE_DIR_UNKNOWN is
 * the honest answer when no clear edge signal exists -- an
 * un-inferable probe is keyed under UNKNOWN rather than force-fit to
 * a guessed direction.
 */
enum cmp_range_direction {
	CMP_RANGE_DIR_UNKNOWN = 0,
	CMP_RANGE_DIR_ASCENDING,	/* most-recent exemplar at the high end */
	CMP_RANGE_DIR_DESCENDING,	/* most-recent exemplar at the low end */
};

/*
 * Signedness is part of identity (same discipline as the
 * discriminated-arg width/sign handling): a 4-byte signed range whose
 * bounds straddle the signed/unsigned boundary is NOT the same probe
 * as an 8-byte unsigned range with the same numeric bounds.  Inferred
 * from whether either bound has the sign bit of its width set.
 */
enum cmp_range_signedness {
	CMP_RANGE_SIGN_UNSIGNED = 0,
	CMP_RANGE_SIGN_SIGNED,
};

/*
 * Relation class describes how the kernel-side compare uses the
 * range.  KCOV records only matching observed operands, so every
 * cluster the observer accumulates is INSIDE by construction; the
 * other classes ship for the future consumer-side probe ladder
 * (outside / single-bound / wrap-around arms) and stay populated
 * by later inference passes.
 */
enum cmp_range_relation {
	CMP_RANGE_REL_INSIDE = 0,	/* value lies within [lo, hi] */
	CMP_RANGE_REL_OUTSIDE,
	CMP_RANGE_REL_BOUND,
	CMP_RANGE_REL_WRAP,
	CMP_RANGE_REL_UNKNOWN,
};

/*
 * Common shape across every hypothesis kind.  Fields not relevant to a
 * given kind are zero (e.g. mask is unused by CMP_HYP_EXACT, lo/hi by
 * CMP_HYP_BITMASK).  Counters are saturating uint64_t for shadow-phase
 * accumulation -- the active inference + feedback layers will land in
 * the follow-up units and bound the lifetime + decay policy.
 *
 * cmp_ip is current-kernel-only and optional: cross-kernel persistence
 * drops it on load (the kallsyms fingerprint on the on-disk file
 * already invalidates IP keys across rebuilds), so consumers must
 * tolerate a zero ip on a warm-started entry.
 *
 * range_direction / range_signedness / range_relation are populated
 * only for CMP_HYP_RANGE entries and participate in their dedup key;
 * for every other kind they are zero and ignored.
 */
struct cmp_hypothesis {
	unsigned int nr;
	bool do32;
	uint8_t width;			/* operand width in bytes: 1, 2, 4, or 8 */
	uint8_t kind;			/* enum cmp_hypothesis_kind */
	uint8_t state;			/* enum cmp_hypothesis_state */
	uint8_t score_bucket;
	uint8_t range_direction;	/* enum cmp_range_direction (RANGE only) */
	uint8_t range_signedness;	/* enum cmp_range_signedness (RANGE only) */
	uint8_t range_relation;		/* enum cmp_range_relation (RANGE only) */
	uint64_t cmp_ip;
	uint64_t lo;
	uint64_t hi;
	uint64_t mask;
	uint64_t exemplar;
	uint64_t seen_count;
	uint64_t consumed_count;
	/*
	 * Per-hypothesis SHADOW outcome counters.  Bumped by
	 * cmp_hyp_credit_outcome() on the would-have-been-chosen hypothesis
	 * resolved from a (cmp_ip, value, width) tuple at credit time.  Per
	 * the [11-feedback-loop] discipline cmp_novelty_wins is kept
	 * SEPARATE from pc_wins so harvested-but-flat CMP novelty cannot
	 * masquerade as a PC-edge conversion.  Saturating semantics: bumps
	 * are RELAXED, a u64 cannot realistically wrap inside any single
	 * fuzz run.  All fields are zero until a credit fires; the live
	 * pick path does NOT read them.
	 */
	uint64_t pc_wins;
	uint64_t transition_wins;
	uint64_t cmp_novelty_wins;
	uint64_t corpus_save_wins;
	uint64_t misses;
	uint64_t disabled_skips;
	uint64_t destructive_skips;
	uint64_t context_skips;
	uint64_t last_used_generation;
};

/*
 * Hard caps per syscall + per kind.  Keeps the store bounded under the
 * worst-case fuzz workload: a single syscall whose comparisons explode
 * across every kind can populate at most CMP_HYP_KIND_NR *
 * CMP_HYP_PER_KIND entries, and no single kind can starve the others
 * out of its slots.  cmp_hyp_observe() honours the partition via
 * per_kind_count[]: an exhausted kind bumps cmp_hyp_kind_full and
 * leaves the other kinds free, while an exhausted total bumps
 * cmp_hyp_pool_full.
 *
 * CMP_HYP_PER_KIND was raised from 2 to 16 after first telemetry: at 2,
 * cmp_hyp_kind_full ran ~2x cmp_hyp_observations (the EXACT and
 * ENUM_FAMILY lanes fire on every observation and saturate their two
 * slots almost immediately), so nearly every observation was dropped at
 * insert and the parallel store stayed effectively empty.  16 gives each
 * kind room for the distinct comparison sites a busy syscall exercises
 * while staying memory-bounded.
 *
 * Footprint is sizeof(struct cmp_hypothesis) (144 B) * CMP_HYP_PER_KIND *
 * CMP_HYP_KIND_NR per pool, over a hyp_pools[MAX_NR_SYSCALL][2] grid.  At
 * 16 that is 144 * 16 * 8 = 18432 B of entries per pool, ~18472 B per
 * pool with the header, and ~36 MiB across the 2048-pool grid (up from
 * ~4.6 MiB at 2).  The grid is shared memory allocated once at init; the
 * biarch [*][1] half is unused on uniarch builds, mirroring the existing
 * cmp_hint_pool grid's identical waste.
 */
#define CMP_HYP_PER_KIND	16U
#define CMP_HYP_PER_SYSCALL	(CMP_HYP_KIND_NR * CMP_HYP_PER_KIND)

struct cmp_hyp_pool {
	unsigned int count;
	unsigned int per_kind_count[CMP_HYP_KIND_NR];
	struct cmp_hypothesis entries[CMP_HYP_PER_SYSCALL];
};

/*
 * Fleet-wide shared cmp_ip tier.
 *
 * Cross-syscall fallback bank: keyed on canonical (KASLR-stripped)
 * cmp_ip ALONE, unlike the per-nr pools above which are keyed on
 * (nr, cmp_ip, value, size).  A single kernel comparison site that
 * fires under many syscalls (do_syscall_64 / seccomp gates, iov walk,
 * copy_from_user length checks, kcov entry gate, ...) produces the
 * SAME canonical cmp_ip regardless of which syscall drove the child;
 * the shared tier collapses those cross-nr duplicates into ONE
 * value-set entry so a cold per-nr pool can eventually warm-start
 * from constants ANY sibling syscall already learned at the same
 * check.  Validated by the overlap-mine: ~48% of cmp_ips are shared
 * across nrs and ~87% of learned entries are cross-nr duplicates.
 *
 * The per-nr pools stay AUTHORITATIVE; the shared tier is fallback /
 * warm-start ONLY -- it never displaces a per-nr entry, never gates
 * a per-nr pick, and never replaces a value the per-nr picker would
 * have served on its own.  Storage is a fixed-size open-addressed
 * hash table (CMP_SHARED_TIER_IPS buckets, power-of-two so the mask
 * beats a modulo) with bounded linear probe on collision.  Probe
 * exhaustion silently drops the record: the tier is advisory,
 * dropping is the same shape as the per-nr LRU eviction.
 *
 * Per-bucket value-set holds up to CMP_SHARED_TIER_VALUES distinct
 * (value, size) pairs at the same cmp_ip -- a busy comparison site
 * (switch dispatch, enum-family compare) legitimately carries many
 * constants, but past ~8 the incremental value flattens; overflow
 * drops silently (tier is fallback tier, not authoritative).
 *
 * Entry-path filter.  A cmp_ip that fires under every syscall (the
 * shared-with-fleet entry path: do_syscall_64, seccomp, kcov gate,
 * copy_from_user length probes, ...) is noise as a warm-start seed:
 * a value learned at "iov->iov_len < LONG_MAX" tells the picker
 * nothing about which value to feed a specific syscall arg.  Track
 * distinct-nr-count per bucket; once it crosses
 * CMP_SHARED_TIER_ENTRY_PATH_NR_MAX (~15% of MAX_NR_SYSCALL, sized
 * off the overlap mine) latch entry_path_excluded and stop counting
 * this bucket toward the shadow warm-start eligibility metric.  The
 * bucket keeps STORING contributions (so a follow-up analysis can
 * still probe the entry-path population) but is excluded from the
 * shadow observer's supply signal.
 *
 * NOT persisted by cmp_hints_save_file -- the tier is DERIVED from
 * the per-nr pools on warm-load (walk pools[][] and union each
 * live entry into the tier) and topped up on every fresh commit
 * (pool_add_locked() success), so the persisted per-nr snapshot is
 * a complete on-disk representation and no new on-disk schema is
 * needed.
 */
#define CMP_SHARED_TIER_IPS			2048U
#define CMP_SHARED_TIER_VALUES			8U
#define CMP_SHARED_TIER_ENTRY_PATH_NR_MAX	150U
#define CMP_SHARED_TIER_PROBE_MAX		8U

/*
 * Rollout gate for the shared cmp_ip tier -- same OFF / SHADOW_ONLY /
 * COMBINED ramp discipline the sibling cost_pool_selector_mode and
 * frontier_saturation_cooldown_mode rows use.
 *
 *   OFF          - default, byte-identical to a build before the tier
 *                  landed.  Every hot-path shared-tier access (both
 *                  the collect-side insert and the get-side shadow
 *                  probe) short-circuits before touching the tier
 *                  shm.  Under a fixed-seed --dry-run the pick stream
 *                  and every counter are bit-for-bit identical to a
 *                  pre-shared-tier build.
 *   SHADOW_ONLY  - the collect-side insert populates the tier (both
 *                  at warm-load from cmp_hints_load_file and live on
 *                  every fresh pool_add_locked success), and the
 *                  get-side probe bumps cmp_shared_tier_shadow_warm
 *                  start_eligible on every per-nr cold miss where the
 *                  tier has a non-entry-path IP available to seed
 *                  from.  Live selection stays unchanged: try_get
 *                  returns exactly what it would have returned
 *                  without the observer.  Zero RNG consumption on the
 *                  probe path.
 *   COMBINED     - Live serve enabled AND quarantined.  In addition
 *                  to the SHADOW_ONLY behaviour above,
 *                  cmp_shared_tier_try_serve_cold_miss() fires on a
 *                  per-nr cold miss (durable pool empty on the
 *                  requested (nr, do32), recent-tier pre-pass
 *                  returned MISS) and, gated by a
 *                  ONE_IN(CMP_SHARED_TIER_SERVE_DICE) budget,
 *                  elects an occupied non-entry-path bucket at
 *                  random and returns one of its (value, size)
 *                  pairs.  The served value is stamped
 *                  served_from_shared=1 on the per-child stash so
 *                  the credit drain routes its PC outcome to
 *                  cmp_hint_tier_shared_wins / _misses ONLY and
 *                  does NOT touch native pool per-entry / by-pool /
 *                  by-callsite / by-tier / by-age credit.  A
 *                  constant served from the shared tier NEVER
 *                  becomes native pool provenance under this path
 *                  -- promotion requires separate local
 *                  re-observation via cmp_hints_collect().  Native
 *                  warm hits are strictly preferred: the serve
 *                  fires only after every native tier (recent ring,
 *                  durable per-nr pool) has been consulted and
 *                  missed.
 *
 * Param-settable from --cmp-shared-tier=off|shadow|combined.
 */
enum cmp_shared_tier_mode {
	CMP_SHARED_TIER_MODE_OFF = 0,
	CMP_SHARED_TIER_MODE_SHADOW_ONLY = 1,
	CMP_SHARED_TIER_MODE_COMBINED = 2,
};

extern enum cmp_shared_tier_mode cmp_shared_tier_mode;

_Static_assert((CMP_SHARED_TIER_IPS & (CMP_SHARED_TIER_IPS - 1)) == 0,
	       "CMP_SHARED_TIER_IPS must be a power of two");

struct cmp_shared_tier_entry {
	unsigned long value;
	uint32_t size;		/* operand width in bytes: 1, 2, 4, or 8 */
	uint32_t pad;		/* explicit 8-byte alignment */
};

/*
 * Occupancy is gated on the `occupied` byte (RELEASE-store on claim,
 * ACQUIRE-load on read) so a lockless reader that observes occupied=1
 * is guaranteed to see cmp_ip / values[] / value_count / seen_nrs[]
 * populated behind it.  All writes on an occupied bucket happen under
 * the shared_tier_lock in cmp_hints_shared below; only the initial
 * claim uses the RELEASE-store to publish the key without needing a
 * distinct probe-side lock.
 *
 * seen_nrs[] is a 1024-bit membership bitmap indexed by syscall nr:
 * bit set => this nr has contributed to this cmp_ip before.  A fresh
 * bit-set bumps distinct_nr_count; do32 is folded into "nr" for the
 * count (a 64-bit and a 32-bit syscall at nr=N contribute the same
 * bit -- the entry-path filter is about the shape "this IP fires
 * across many callers", not "this IP fires under two architectures").
 */
struct cmp_shared_tier_bucket {
	unsigned long cmp_ip;
	uint32_t distinct_nr_count;
	uint16_t value_count;
	uint8_t occupied;
	uint8_t entry_path_excluded;
	struct cmp_shared_tier_entry values[CMP_SHARED_TIER_VALUES];
	uint8_t seen_nrs[(MAX_NR_SYSCALL + 7) / 8];
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
	/* Field-scoped attribution table.  Bucket occupancy is gated on
	 * field_pools[i].key.desc; an all-zero memset at init leaves every
	 * bucket empty until claimed by the first matching CMP record. */
	struct cmp_field_pool field_pools[CMP_FIELD_POOL_BUCKETS];
	/* Run-local recent tier.  Memset to zero at
	 * init alongside the rest of the shm allocation; not persisted by
	 * cmp_hints_save_file (the save path only writes pools[]). */
	struct cmp_recent_pool recent_pools[MAX_NR_SYSCALL][2];
	/*
	 * Quarantined childop lane.  Identical shape to recent_pools
	 * above; populated only when --childop-cmp-harvest=on and a
	 * trinity_cmp_syscall() inside a kcov_cmp_bracket harvests CMP
	 * records keyed by the wrapped syscall's real __NR_X.
	 *
	 * Source-tagged by storage (this dedicated grid -- NOT mixed
	 * into the durable per-syscall pool grid above) so childop
	 * constants cannot evict random-syscall constants out of the
	 * 16-entry durable LRU.  Per the design
	 * (projects/trinity/childop-cmp-integration-design.md §3.1),
	 * promotion of a per-nr slice into the shared durable pool is a
	 * separate quota-gated C6 step earned by the §4 conversion-chain
	 * metrics; until then this lane is the only sink for childop CMP
	 * constants.
	 *
	 * Not persisted by cmp_hints_save_file -- the save path only
	 * writes pools[], identical to recent_pools[] above.  Memset to
	 * zero at init alongside the rest of the shm allocation.
	 */
	struct cmp_recent_pool childop_recent_pools[MAX_NR_SYSCALL][2];
	/* SHADOW typed-hypothesis store.  Zero-initialised by the same
	 * memset that clears the rest of cmp_hints_shared; written by
	 * cmp_hyp_observe() under the matching durable cmp_hint_pool lock
	 * and not yet read by any consumer or injection path. */
	struct cmp_hyp_pool hyp_pools[MAX_NR_SYSCALL][2];
	/*
	 * Fleet-wide shared cmp_ip tier.  Single global lock covers every
	 * bucket -- the insert path fires only on a per-nr pool_add_locked()
	 * SUCCESS (fresh insert / evict-replace), which is rare against the
	 * per-record collect volume once the bloom + strip filters absorb
	 * the dedup load; a global lock here trades a bounded serialisation
	 * point for 2048 * sizeof(lock_t) of extra shm the per-bucket lock
	 * grid would cost, plus a matching entry in every check_all_locks()
	 * walk.  Bucket occupancy uses the acquire/release pair on
	 * buckets[i].occupied for the read path so the shadow probe stays
	 * lock-free -- the lock only covers write-side content changes.
	 */
	lock_t shared_tier_lock;
	struct cmp_shared_tier_bucket shared_tier[CMP_SHARED_TIER_IPS];
};
_Static_assert(MAX_NR_SYSCALL == 1024,
	"cmp_hints_shared layout assumes MAX_NR_SYSCALL == 1024");

extern struct cmp_hints_shared *cmp_hints_shm;

/* Called once from init_shm() to allocate shared hint storage. */
void cmp_hints_init(void);

/* Extract comparison operands from a CMP-mode trace buffer and
 * add interesting constants to the hint pool for syscall nr. */
void cmp_hints_collect(unsigned long *trace_buf, unsigned int nr, bool do32);

/*
 * Childop quarantine-lane insert.  Writes (cmp_ip, val, size) into
 * cmp_hints_shared.childop_recent_pools[nr][do32] using the same
 * head-advance + saturating-count ring discipline cmp_recent_insert()
 * uses for the run-local recent ring.  Bumps kcov_shm
 * ->childop_cmp_pool_inserts[nr] on every call and
 * ->childop_cmp_pool_evicts[nr] when the ring slot being overwritten
 * was already populated.
 *
 * Single-writer per (nr, do32): every caller is inside a
 * trinity_cmp_syscall() under a kcov_cmp_bracket on a CMP-mode child,
 * and a CMP-mode child holds exactly one bracket at a time, so the
 * ring writes need no lock.  Readers in the eventual consume side
 * tolerate a torn (cmp_ip, value, size) triplet identically to how
 * cmp_hints_try_get_ex() reads the recent ring today -- advisory
 * values, advisory pool.
 *
 * No dedup -- the ring deliberately accepts the same (cmp_ip, val,
 * size) tuple again so "recent" semantics aren't diluted by
 * collapsing a tuple the kernel saw twice into one slot.  Out-of-
 * range nr / NULL shm / oversize ring head are silently dropped (the
 * harvest path is advisory; see §3.1).
 */
void cmp_hints_childop_insert(unsigned int nr, bool do32,
			      unsigned long cmp_ip, unsigned long val,
			      unsigned int size);

/*
 * SHADOW typed-hypothesis observation hook.
 *
 * Called from cmp_hints_flush_pending() once per fresh insert into the
 * durable per-syscall pool, still under that pool's lock.  Drives the
 * typed inference lanes (EXACT / BITMASK / ENUM_FAMILY / RANGE) and
 * bumps the cmp_hyp_* shadow counters; does NOT influence injection or
 * the live cmp-hint pick.  Out-of-range nr / unsupported size / NULL
 * shm are bailed early.
 */
void cmp_hyp_observe(unsigned int nr, bool do32, unsigned long cmp_ip,
		     unsigned long value, unsigned int size);

/*
 * SHADOW per-hypothesis feedback outcome menu.  Each enumerator names a
 * channel cmp_hyp_credit_outcome() can credit to the would-have-been-
 * chosen hypothesis at the matching (nr, do32, cmp_ip, value, width)
 * tuple.  CMP_NOVELTY is deliberately a peer of PC_WIN rather than a
 * variant: harvested-but-flat novelty must never be folded into PC-edge
 * conversion accounting ([11-feedback-loop] discipline).  CORPUS_SAVE /
 * DESTRUCTIVE_SKIP / CONTEXT_SKIP are part of the published menu so the
 * struct is laid out for the consumer + skip-site wiring that lands in
 * follow-up units; until then those channels never fire and the per-
 * hypothesis counters stay zero.
 */
enum cmp_hyp_outcome {
	CMP_HYP_OUTCOME_PC_WIN,
	CMP_HYP_OUTCOME_TRANSITION_WIN,
	CMP_HYP_OUTCOME_CMP_NOVELTY,
	CMP_HYP_OUTCOME_CORPUS_SAVE,
	CMP_HYP_OUTCOME_MISS,
	CMP_HYP_OUTCOME_DISABLED,
	CMP_HYP_OUTCOME_DESTRUCTIVE_SKIP,
	CMP_HYP_OUTCOME_CONTEXT_SKIP,
	CMP_HYP_OUTCOME_NR,
};

/*
 * SHADOW per-hypothesis feedback credit.
 *
 * Resolve the would-have-been-chosen hypothesis at hyp_pools[nr][do32]
 * from the (cmp_ip, value, width) tuple via the same EXACT > ENUM_FAMILY
 * > BITMASK > RANGE specificity ladder the consumer side will use, then
 * bump the matching per-hypothesis outcome counter and the matching
 * cmp_hyp_* flat counter in kcov_shm.  Out-of-range nr / unsupported
 * size / NULL shm / no-matching-hypothesis are bailed silently (advisory
 * shadow accounting -- a credit that finds no hypothesis is just an
 * unobserved value, never a correctness issue).
 *
 * Does NOT influence injection or the live cmp-hint pick: the function
 * is a write-only sink against the parallel hyp_pools[] grid.  Callers
 * pass the same (cmp_ip, value, size) tuple they stashed at hint-pull
 * time so the credit lands on the hypothesis whose typed inference
 * explains the picked value.
 */
void cmp_hyp_credit_outcome(unsigned int nr, bool do32, unsigned long cmp_ip,
			    unsigned long value, unsigned int size,
			    enum cmp_hyp_outcome outcome);

/*
 * Use-case taxonomy for the cmp-hint consumer.  cmp_hints_try_get_ex()
 * selects an output transform from the use case (and, in a follow-up,
 * from the pool entry's recorded comparison width).  Callers that today
 * only need the historical {C-1, C, C+1} boundary triple stay on the
 * cmp_hints_try_get() wrapper, which routes to CMP_HINT_BOUNDARY.
 *
 *   CMP_HINT_EXACT      Return C unchanged.  For cmd codes, enum
 *                       selectors, version magics -- any slot whose
 *                       gate is an equality test.  Boundary +/-1 would
 *                       silently reject these.
 *   CMP_HINT_BOUNDARY   Rotate uniformly among {C-1, C, C+1}.  For
 *                       length / size / range checks: probes the
 *                       "<", "<=", ">", ">=" boundaries that bare
 *                       equality leaves unsatisfied.  Historical
 *                       behaviour; the wrapper's default.
 *   CMP_HINT_FLAG_MASK  Mix C with the caller's existing mask: rotate
 *                       uniformly among {old|C, old&~C, old^C}.  For
 *                       flag-bitmask slots where C is a single bit (or
 *                       narrow group) and the caller already has a
 *                       running mask -- bare C would clobber it.  When
 *                       old == 0 the function degrades to bare C (no
 *                       signal to mix with).
 *   CMP_HINT_FIELD      Placeholder for the field-scoped pool lookup.
 *                       Today's behaviour is identical to
 *                       CMP_HINT_EXACT -- field-scoped pools do not
 *                       exist yet so there is nothing to look up
 *                       against; the use case ships here so the caller
 *                       surface settles before the consumer side lands.
 *
 * Width-aware masked/sign-extended transforms per comparison size are
 * called out in the spec as a fourth transform family and will land in
 * a follow-up: the pool entry already carries the recorded comparison
 * width, but the existing four callsites in generate-args.c return
 * full-long values and a silent narrowing here would change their
 * behaviour.  The wrapper split deliberately keeps the wrapper
 * byte-for-byte equivalent to today; width-aware lands once a callsite
 * opts in.
 */
enum cmp_hint_use {
	CMP_HINT_EXACT,
	CMP_HINT_BOUNDARY,
	CMP_HINT_FLAG_MASK,
	CMP_HINT_FIELD,
};

/*
 * Argtype-handler callsite the cmp_hints_try_get*() pull came from.
 * Stamped on the per-child consume stash so the credit drain can
 * partition the PC-mode outcome (wins/misses) by callsite, closing
 * the "callsite split exists for INJECTED only, win split exists
 * for POOL only" gap.  Aggregated across all syscalls (the per-nr
 * split lives in per_syscall_cmp_injected / _wins).  Append-only:
 * callers keying on a slot index (kcov_shm counter arrays sized by
 * CMP_HINT_CALLSITE_NR, stats/kcov_cmp.c render table) depend on
 * the ordering being stable across builds.
 */
enum cmp_hint_callsite {
	CMP_HINT_CALLSITE_ARG_OP = 0,
	CMP_HINT_CALLSITE_ARG_LIST,
	CMP_HINT_CALLSITE_ARG_UNDEFINED,
	CMP_HINT_CALLSITE_ARG_STRUCT_SIZE,
	CMP_HINT_CALLSITE_STRUCT_FIELD,
	CMP_HINT_CALLSITE_OTHER,
	/* The ARG_RANGE accept-path in handle_arg.c buckets here rather
	 * than in OTHER so the typed-eligible baseline (ARG_STRUCT_SIZE +
	 * ARG_RANGE) can be read cleanly out of the callsite split without
	 * OTHER also carrying any future non-classified sites. */
	CMP_HINT_CALLSITE_ARG_RANGE,
	CMP_HINT_CALLSITE_NR,
};

/* Caller-supplied hard accept range for the value the consumer is
 * about to commit.  When non-NULL, cmp_hints_try_get_ex() applies an
 * inclusive [lo, hi] gate at the served-value site of each tier and
 * fails the pull on a miss without bumping any per-pull counter or
 * stashing for credit.  NULL means accept-all (the historical
 * behaviour).  ARG_RANGE is the only current caller that uses a
 * non-NULL range; without the gate the durable-tier inject path
 * credited and counted the derived value before the caller's
 * post-return range check could reject it, contaminating
 * cmp_hyp_live_injected (the denominator) and cmp_hyp_pc_wins (the
 * arm-verdict numerator) with values that never reached the
 * kernel. */
struct cmp_accept_range {
	unsigned long lo;
	unsigned long hi;
};

/* Extract a random hint value for the given syscall and apply the
 * use-case-driven output transform.  Returns true with the transformed
 * hint written to *out, or false on chaos-gate suppression / empty pool
 * / corrupted pool / out-of-range nr / accept-range miss.  do32 selects
 * between the 64-bit and 32-bit syscall-table pools so biarch builds
 * do not contend for the same per-nr dedup slots.  old is consumed
 * only by CMP_HINT_FLAG_MASK; pass 0 from other call sites.
 *
 * On every successful return a SHADOW would-pick resolver is invoked
 * over the typed hypothesis store for the same (nr, do32, cmp_ip,
 * width), bumping the cmp_hyp_would_pick_by_kind / would_miss_by_kind
 * / would_value_differs counters in kcov_shm.  The shadow walk runs
 * regardless of arm so the would-pick rate stays comparable across
 * runs.
 *
 * allow_hyp_inject opts the caller into the LIVE typed-hypothesis
 * inject arm: a callsite whose argtype is on the typed-safe set
 * (ARG_RANGE, ARG_STRUCT_SIZE, cataloged size/count/range scalars,
 * timespec-bounded) passes true and, when the conservative gate
 * (plateau == CMP_RISING_PC_FLAT AND ONE_IN(4)) fires AND the
 * resolver has a hypothesis at the same (cmp_ip, width), the raw
 * pool value the pick step computed is replaced by a value derived
 * from that hypothesis (EXACT exemplar / ENUM_FAMILY exemplar or
 * lo/hi / BITMASK single set-bit / RANGE lo/hi/mid).  Callers that
 * are NOT typed-safe (broad ARG_OP / ARG_LIST / ARG_UNDEFINED,
 * fd/pid/handle slots, pointer-shaped slots, flags except via
 * BITMASK) pass false and keep the historical raw-pool behaviour
 * byte-for-byte.
 *
 * accept is the caller-supplied hard accept range (see struct
 * cmp_accept_range).  NULL means accept-all; non-NULL gates the
 * post-transform / post-inject value against [lo, hi] inclusive and
 * fails the pull on a miss before any per-pull counter or stash
 * fires, so a rejected value cannot contaminate either the
 * cmp_hyp_live_injected denominator or the cmp_hyp_pc_wins numerator
 * downstream.
 *
 * arg_idx is the caller's syscall argnum (1..6) for the arg slot the
 * returned value is about to be COMMITTED to.  Value-neutral: it feeds
 * the typed_inject_fill_slot_hist[] placement-proof counter only --
 * the counter is bumped once at the accept-gated commit block when the
 * LIVE typed inject actually fired (hyp_injected).  Callers on the
 * typed-eligible set (allow_hyp_inject == true) pass their argnum
 * verbatim; non-typed callers pass 0 (the bump site's slot bound
 * check drops out-of-range indices, and hyp_injected can only be true
 * under allow_hyp_inject, so 0 is safe by construction).  No rnd_*()
 * draw and no derived-value change is added by this parameter. */
bool cmp_hints_try_get_ex(unsigned int nr, bool do32, enum cmp_hint_use use,
			  unsigned long old, bool allow_hyp_inject,
			  const struct cmp_accept_range *accept,
			  unsigned int arg_idx,
			  enum cmp_hint_callsite callsite,
			  unsigned long *out);

/* Back-compat wrapper.  Routes to CMP_HINT_BOUNDARY with old == 0 and
 * keeps the live typed-hypothesis inject arm OFF so the existing
 * non-typed-safe call sites in generate-args.c retain the pre-split
 * {C-1, C, C+1} rotation byte-for-byte until each is individually
 * migrated to the use case (and inject opt-in) that fits its
 * consumer slot. */
bool cmp_hints_try_get(unsigned int nr, bool do32,
		       enum cmp_hint_callsite callsite,
		       unsigned long *out);

/* Width-preserving variant of cmp_hints_try_get().  Same policy
 * (CMP_HINT_BOUNDARY rotation, no typed-hypothesis inject arm, no
 * accept range) but on a true return also writes the pool entry's
 * recorded operand width (uint32_t size in {1, 2, 4, 8}) into
 * *out_size.  Consumers that splat the returned constant into a
 * byte buffer (the blob mutator's CMPDICT learned arm) use this to
 * write the constant at the width the kernel's cmp instruction
 * actually reads, rather than a width chosen independently of the
 * pool entry's provenance.  On a false return *out_size is left
 * unchanged. */
bool cmp_hints_try_get_sized(unsigned int nr, bool do32,
			     enum cmp_hint_callsite callsite,
			     unsigned long *out, unsigned int *out_size);

/*
 * Field-scoped hint pull.  Locates the field pool keyed by
 * (desc, nr, do32, arg_idx, field_idx, size) via the same hash + ACQUIRE
 * probe loop the recorder uses, picks one entry uniformly at random, and
 * routes the result through cmp_hint_apply_transform() before writing it
 * to *out.  Bumps cmp_field_consumer_would_pick / would_miss / pool_empty
 * / key_absent counters on every call regardless of the LIVE arm state so
 * the would-pull distribution is observable from a default run; only the
 * LIVE arm actually returns a value and stashes it for credit.  Returns
 * false on chaos suppression / corrupted pool / out-of-range key / SHADOW
 * arm.  Caller contract mirrors cmp_hints_field_record(): nr <
 * MAX_NR_SYSCALL, arg_idx in 1..6, size in {1,2,4,8}, desc != NULL.
 *
 * fallback carries the value the generator would OTHERWISE write to the
 * slot if this pull did not fire (i.e. the pre-hint value already sitting
 * in the destination).  Consumed only by the SHADOW would_value_differs
 * measurement -- compared against the elected pool entry's value to bump
 * the differs win-scalar on the subset where a live-arm flip would
 * actually change the byte on the wire.  Does not influence pick / miss
 * / key-absent counting and does not affect the returned value.
 */
bool cmp_hints_field_try_get(unsigned int nr, bool do32, unsigned int arg_idx,
			     const struct struct_desc *desc,
			     unsigned int field_idx, unsigned int size,
			     enum cmp_hint_use use, unsigned long old,
			     unsigned long fallback, unsigned long *out);

/*
 * SHADOW per-entry feedback scoring for hint consumption -- the
 * recording half of the score-based feedback loop.
 *
 * cmp_hints_try_get_ex() stashes (nr, arch, pool-kind, cmp_ip, value,
 * size, transform) into a small per-child ring on each successful
 * return.  dispatch_step()'s post-call bookkeeping drains the ring via
 * exactly ONE of the three credit calls below per parent dispatch,
 * then resets it.  Today the credit is OBSERVATION-ONLY: it updates
 * the cmp_hint_wins / cmp_hint_misses / cmp_hint_cmp_novelty_wins flat
 * counters in kcov_shm and the per-entry wins/misses on the matching
 * pool entry.  The SHADOW phase is measurement-first: live pool
 * selection stays uniform while these counters accumulate.  A future
 * A/B-gated weighted live-pick policy
 * (`weight = floor + wins*4 - misses` clamped, keeping random
 * exploration) will consume the score.
 *
 * pool_kind partitions the stash by which pool the hint came from so
 * the follow-up can score per-kind independently.  Both pools now have
 * consumers wired; the field-scoped consumer runs in SHADOW today
 * (bumps would-pick / would-miss counters but does not affect the live
 * pick, which stays per-syscall) and a follow-up flips it LIVE once
 * the shadow signal is validated against a real run.
 */
enum cmp_hint_pool_kind {
	CMP_HINT_POOL_PER_SYSCALL = 0,
	CMP_HINT_POOL_FIELD,
	CMP_HINT_POOL_KIND_NR,
};

/*
 * Per-child stash entry recording one cmp_hints_try_get_ex() return.
 * Sized to 40 bytes after the field-scoped widen (arg_idx / field_idx /
 * desc).  The historical 24-byte layout carried only the per-syscall
 * key (nr + cmp_ip); the field-scoped credit drain re-finds its bucket
 * via cmp_field_pool_hash(desc, nr, do32, arg_idx, field_idx, size), so
 * every field key component must round-trip through the stash.  The
 * extra fields are NULL/0 for per-syscall pool kinds; only the
 * CMP_HINT_POOL_FIELD branch populates them.  The 8-deep stash now
 * spans five cachelines on the childdata struct (was three); 8 entries
 * still covers the maximum hint-consuming-arg count with headroom.
 */
struct cmp_hint_consumed_entry {
	unsigned long cmp_ip;
	unsigned long value;
	const struct struct_desc *desc;	/* NULL for CMP_HINT_POOL_PER_SYSCALL */
	uint16_t nr;
	uint16_t field_idx;		/* 0 for CMP_HINT_POOL_PER_SYSCALL */
	uint8_t do32;
	uint8_t pool_kind;		/* enum cmp_hint_pool_kind */
	uint8_t size;
	uint8_t transform;		/* enum cmp_hint_use */
	uint8_t arg_idx;		/* 1-based, 0 for CMP_HINT_POOL_PER_SYSCALL */
	/* Freshness / tier breadcrumbs stamped at pick time and consumed
	 * by cmp_hints_feedback_credit_pc() so the per-tier and per-age
	 * cmp_hint_tier_*_wins / cmp_hint_durable_age_*_wins counters in
	 * kcov_shm partition the PC-mode outcome by where the hint came
	 * from and how stale it was when picked.  Recent-ring picks set
	 * served_from_recent=1 and age_bucket=0 (the ring has no per-entry
	 * LRU stamp; its freshness story is the tier itself).  Durable
	 * picks (per-syscall pool, field pool) set served_from_recent=0
	 * and age_bucket = cmp_hint_age_bucket(pool->last_used_stamp -
	 * picked->last_used) measured lock-free at pick time, tolerant of
	 * a torn read in exactly the same way the rest of the pick path
	 * is: a single misbucketed sample is advisory shadow accounting,
	 * not a correctness issue. */
	uint8_t served_from_recent;	/* 1 == recent ring, 0 == durable */
	uint8_t age_bucket;		/* 0..CMP_HINT_AGE_BUCKETS-1 */
	/* enum cmp_hint_callsite the pull came from, stamped at consume
	 * time from the try_get_ex()/try_get() caller's known callsite so
	 * the credit drain can partition the PC-mode outcome by callsite
	 * (cmp_hint_callsite_pc_wins[] / cmp_hint_callsite_misses[]) in
	 * lock-step with the existing by-pool partition.  Sentinel value
	 * CMP_HINT_CALLSITE_NR means "unclassified" -- used by field-pool
	 * pulls (cmp_hints_field_try_get) that have no argtype-handler
	 * callsite; the drain gates the by-callsite bump on
	 * < CMP_HINT_CALLSITE_NR so an unclassified stash entry is
	 * silently skipped rather than misattributed. */
	uint8_t callsite;		/* enum cmp_hint_callsite, NR == unset */
	/* 1 == value came from the live typed-hypothesis inject arm at
	 * pick time, 0 == raw pool value (the unchanged historical
	 * path).  Read by the credit drain to gate
	 * cmp_hyp_credit_outcome(): under shadow, the drain credited
	 * the hyp store on every pull, so cmp_hyp_pc_wins counted raw
	 * replays that coincidentally matched a stored hypothesis.
	 * Under the live arm, the drain credits cmp_hyp_pc_wins ONLY
	 * for stash entries the live inject produced, so the counter
	 * finally measures real hypothesis-derived conversion rather
	 * than coincidence. */
	uint8_t hyp_injected;
	/* 1 == value came from the quarantined shared-tier COMBINED-mode
	 * serve at pick time (cmp_shared_tier_try_serve_cold_miss); 0 ==
	 * native pool / recent ring value.  The credit drain routes the
	 * PC outcome for shared-served entries to
	 * cmp_hint_tier_shared_wins / cmp_hint_tier_shared_misses ONLY
	 * and SKIPS the native pool per-entry credit, the by-pool /
	 * by-callsite / by-tier / by-age partitions, and the typed-hyp
	 * consume/would-pick credit.  A shared-served constant must not
	 * pollute native pool provenance because it was never locally
	 * re-observed; promotion to native evidence requires
	 * cmp_hints_collect() picking the same (cmp_ip, value, size) up
	 * from the kernel independently.  Mutually exclusive with
	 * served_from_recent / hyp_injected by construction: the serve
	 * path fires only on a native cold miss (recent-tier pre-pass
	 * already returned MISS, durable pool empty) and does not run
	 * the inject arm. */
	uint8_t served_from_shared;
};

#define CMP_HINT_CONSUMED_STASH_MAX	8U

/*
 * Reset the per-child stash without crediting anything.  Called from
 * generate_syscall_args() at the top of a new call so a parent
 * dispatch that bailed before reaching the credit drain does not leak
 * its stash into the next call.
 */
void cmp_hints_feedback_reset_stash(void);

/*
 * Drain the per-child stash and credit the PC-mode call outcome.
 * outcome_win == true bumps cmp_hint_wins and each stashed entry's
 * pool wins counter; outcome_win == false bumps cmp_hint_misses and
 * each stashed entry's pool misses counter.  Always resets the stash
 * on return.  No-op if the stash is empty.
 */
void cmp_hints_feedback_credit_pc(bool outcome_win);

/*
 * Drain the per-child stash and credit CMP-mode novelty.  Bumps
 * cmp_hint_cmp_novelty_wins (SEPARATE from cmp_hint_wins so CMP
 * novelty cannot masquerade as PC-edge conversion -- per spec).
 * Does NOT touch the per-entry pool counters: those are PC-edge
 * scored only.  Always resets the stash on return.
 */
void cmp_hints_feedback_credit_cmp_novelty(void);

/*
 * Walk the per-child stash and credit typed-hyp TRANSITION_WIN /
 * CORPUS_SAVE outcomes for each entry whose hyp_injected flag is set.
 * Does NOT reset the stash -- meant to be called BEFORE
 * cmp_hints_feedback_credit_pc() / _cmp_novelty(), which own the
 * single stash reset at end-of-dispatch.  No-op if the stash is
 * empty.  Typed-hyp credit only; the flat / per-pool / per-tier
 * counters are unaffected.
 */
void cmp_hints_feedback_credit_transition(void);
void cmp_hints_feedback_credit_corpus_save(void);

struct childdata;

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

/*
 * Record a CMP constant attributed to a specific cataloged struct field.
 * Selects (or lazily claims) the bucket keyed by (nr, do32, arg_idx,
 * desc, field_idx, size) and inserts (cmp_ip, val, size) into that
 * pool's entries[] using the same dedup / LRU-eviction discipline as
 * pool_add_locked() for the per-syscall pool.  A field-attribution hit
 * bumps cmp_field_attribution_found; probe-exhaustion (the table is
 * saturated with unrelated keys at all probe positions) bumps
 * cmp_field_attribution_pool_full and silently drops the record --
 * field pools are advisory, never load-bearing.
 *
 * Caller contract: nr < MAX_NR_SYSCALL, arg_idx in 1..6, size in
 * {1,2,4,8}, desc != NULL.  Out-of-range inputs are silently ignored
 * so a hot CMP path that hands a corrupt rec through never destabilises
 * the table.
 */
void cmp_hints_field_record(unsigned int nr, bool do32, unsigned int arg_idx,
			    const struct struct_desc *desc,
			    unsigned int field_idx, unsigned int size,
			    unsigned long val, unsigned long cmp_ip);

/*
 * One-shot self-check called from cmp_hints_init().  Synthesises an
 * insert against a reserved sentinel-nr key, verifies the bucket gets
 * claimed and the field-attribution counter bumps, then clears the
 * bucket back to empty so the live table starts clean.  Proves the
 * recording path is wired end-to-end at every fresh trinity startup --
 * not just at build time.  BUG()s on failure so a regression surfaces
 * loudly at init rather than hiding behind silent zero counters during
 * a run.
 */
void cmp_hints_field_record_self_check(void);
