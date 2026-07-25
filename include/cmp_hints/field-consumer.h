#pragma once

#include <sys/types.h>

#include "cmp_hints/pool.h"
#include "locks.h"

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
