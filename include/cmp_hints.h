#pragma once

#include <sys/types.h>

#include "locks.h"
#include "syscall.h"
#include "types.h"

#include "cmp_hints/pool.h"
#include "cmp_hints/redqueen.h"
#include "cmp_hints/hypothesis.h"
#include "cmp_hints/field-consumer.h"

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
