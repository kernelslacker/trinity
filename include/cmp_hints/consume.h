#pragma once

#include <stdint.h>
#include <sys/types.h>

/*
 * Consume-side types shared by the cmp-hint picker, the credit drain
 * and the per-child stash: the use-case taxonomy, the callsite and
 * pool-kind enums, the accept range and the stash entry.
 */

/*
 * Use-case taxonomy for the cmp-hint consumer.  cmp_hints_try_get_ex()
 * selects an output transform from the use case (and, in a follow-up,
 * from the pool entry's recorded comparison width).  Callers that today
 * only need the historical {C-1, C, C+1} boundary triple pass
 * CMP_HINT_BOUNDARY.
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
};

/*
 * Argtype-handler callsite the cmp_hints_try_get*() pull came from.
 * Stamped on the per-child consume stash so the credit drain can
 * partition the PC-mode outcome (wins/misses) by callsite, closing
 * the "callsite split exists for INJECTED only, win split exists
 * for POOL only" gap.  Aggregated across all syscalls (the per-nr
 * split lives in per_syscall_cmp_injected / _wins).  Append-only:
 * callers keying on a slot index (kcov_shm counter arrays sized by
 * CMP_HINT_CALLSITE_NR, stats/kcov/cmp/periodic.c render table) depend on
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
 * pool_kind records which pool the hint came from and indexes the
 * by-pool counters in kcov_cmp_hint_pool.  CMP_HINT_POOL_KIND_NR is
 * the stamp for a hint no native pool served (the shared-tier
 * bootstrap), which the by-pool partitions skip.
 */
enum cmp_hint_pool_kind {
	CMP_HINT_POOL_PER_SYSCALL = 0,
	CMP_HINT_POOL_KIND_NR,
};

/*
 * Per-child stash entry recording one cmp_hints_try_get_ex() return.
 * The credit drain re-finds the pool entry from (nr, do32, cmp_ip,
 * value, size), so those round-trip through the stash.  The 8-deep
 * stash spans four cachelines on the childdata struct; 8 entries
 * still covers the maximum hint-consuming-arg count with headroom.
 */
struct cmp_hint_consumed_entry {
	unsigned long cmp_ip;
	unsigned long value;
	uint16_t nr;
	uint8_t do32;
	uint8_t pool_kind;		/* enum cmp_hint_pool_kind */
	uint8_t size;
	uint8_t transform;		/* enum cmp_hint_use */
	/* Freshness / tier breadcrumbs stamped at pick time and consumed
	 * by cmp_hints_feedback_credit_pc() so the per-tier and per-age
	 * cmp_hint_tier_*_wins / cmp_hint_durable_age_*_wins counters in
	 * kcov_shm partition the PC-mode outcome by where the hint came
	 * from and how stale it was when picked.  Recent-ring picks set
	 * served_from_recent=1 and age_bucket=0 (the ring has no per-entry
	 * LRU stamp; its freshness story is the tier itself).  Durable
	 * picks set served_from_recent=0
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
	 * CMP_HINT_CALLSITE_NR means "unclassified"; the drain gates the
	 * by-callsite bump on < CMP_HINT_CALLSITE_NR so an unclassified
	 * stash entry is silently skipped rather than misattributed. */
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
