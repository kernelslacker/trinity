#ifndef _CMP_HINTS_INTERNAL_H
#define _CMP_HINTS_INTERNAL_H 1

#include "cmp_hints.h"

/*
 * Internal-only declarations for symbols shared between the compilation
 * units that make up the CMP-hint learning + conversion core: the thin
 * cmp_hints.c orchestrator plus cmp_hints/hyp.c, cmp_hints/pool.c,
 * cmp_hints/field.c, cmp_hints/collect.c, cmp_hints/get.c,
 * cmp_hints/credit.c, and cmp_hints/persist.c.
 *
 * Symbols here were file-static before the TU split.  They are
 * deliberately NOT promoted into the public include/cmp_hints.h --
 * external callers keep going through the public APIs declared there;
 * these declarations widen linkage only as far as the split demands.
 */

/*
 * Per-syscall CMP-collection strip flags.  Definition lives in
 * cmp_hints.c core; cmp_hints_strip_install()/_no_arg_syscalls() write
 * it during init, and cmp_hints_collect() reads it on every trace-buf
 * record.  See the definition-site comment for the biarch semantics.
 */
extern bool cmp_hints_strip[2][MAX_NR_SYSCALL];

/*
 * Per-pool lock helpers.  Wrap plain lock()/unlock() to bump the
 * shared held_count check_all_locks() consults; every cmp_hint_pool
 * mutation goes through this pair.  Definition in cmp_hints/pool.c;
 * cmp_hints/persist.c holds pool->lock for the serialise/restore
 * per-pool memcpy windows.
 */
void pool_lock(struct cmp_hint_pool *pool);
void pool_unlock(struct cmp_hint_pool *pool);

/*
 * Sticky wild-write gate for the per-syscall cmp_hint_pool.  First
 * observation of an OOB count / canary stomp records the channel via
 * kcov_shm counters and latches pool->corrupted.  Definition in
 * cmp_hints/pool.c; every reader across collect/get/credit/persist
 * gates through it before indexing entries[].
 */
bool cmp_hints_pool_corrupted(struct cmp_hint_pool *pool,
			      unsigned int observed_count);

/*
 * Bucket the lock-free LRU-clock delta into CMP_HINT_AGE_BUCKETS
 * coarse log2 ranges.  Bucket 0 == delta 0 (entry is the most
 * recently refreshed in the pool); higher buckets == entry has been
 * carried over many pool mutations since its last_used was bumped.
 * Static-asserted against the kcov_shm array width in the pool
 * cluster.  Inlined here so cmp_hints/get.c and cmp_hints/field.c
 * both see the definition without adding cross-TU call overhead to
 * the pick fast path.
 */
static inline uint8_t cmp_hint_age_bucket(uint64_t age)
{
	if (age == 0)
		return 0;
	if (age < 8)
		return 1;
	if (age < 32)
		return 2;
	if (age < 128)
		return 3;
	if (age < 512)
		return 4;
	if (age < 2048)
		return 5;
	return 6;
}

/*
 * Field-pool sticky wild-write gate.  Independent latch from the
 * per-syscall pool corruption gate so a stomp on a field pool is not
 * folded into the per-syscall pool's corruption rate.  Definition in
 * cmp_hints/field.c; cmp_hints/get.c and cmp_hints/credit.c gate
 * their field-pool readers through it.
 */
bool cmp_field_pool_corrupted(struct cmp_field_pool *pool,
			      unsigned int observed_count);

/*
 * Field-pool bucket hash.  Definition in cmp_hints/field.c; used by
 * the recorder (field.c), the consumer (field.c), the self-check
 * (field.c) and the credit drain (cmp_hints/credit.c) so all four
 * probe the same bucket for a given (desc, nr, do32, arg_idx,
 * field_idx, size) key.
 */
uint32_t cmp_field_pool_hash(const struct struct_desc *desc,
			     unsigned int nr, unsigned int do32,
			     unsigned int arg_idx,
			     unsigned int field_idx,
			     unsigned int size);

/*
 * Per-CMP-record field attribution scan.  Definition in
 * cmp_hints/field.c; called from cmp_hints_collect (collect.c) on
 * every KCOV_CMP record whose arg1 matched a scalar slot.  Walks the
 * dispatching syscall's ARG_STRUCT_PTR_IN/INOUT slots, dereferences
 * the pointed-at struct against the cataloged field layout, and
 * invokes cmp_hints_field_record() on every matching field.
 */
struct syscallrecord;
struct syscallentry;
void cmp_hints_field_scan_record(struct syscallrecord *srec,
				 struct syscallentry *entry,
				 unsigned int nr, bool do32,
				 unsigned long arg1, unsigned long arg2,
				 unsigned int size, unsigned long cmp_ip);

/*
 * Per-child seen-bloom check + set.  Called once per CMP record in
 * cmp_hints/collect.c before the per-pool lock + dedup path; a hit
 * short-circuits the pool_add_locked() round-trip.  Definition in
 * cmp_hints/pool.c alongside the bloom hash helpers.
 */
bool cmp_hints_bloom_check_and_set(struct cmp_hints_bloom *b,
				   unsigned long ip,
				   unsigned long val,
				   unsigned int size);

/*
 * Batched dedup-and-add payload.  cmp_hints_collect() (collect.c)
 * accumulates a per-record batch of these and hands the buffer to
 * cmp_hints_flush_pending() (pool.c) which takes pool->lock once and
 * drains the batch through pool_add_locked().
 *
 * Batch depth balances stack footprint (worst case ~3 KB) against
 * the common case of a hot bloom yielding tens of misses per call --
 * one pool_lock cycle typically drains the whole loop; bursts that
 * overshoot fall back to multiple flushes.
 */
#define CMP_HINTS_PENDING_BATCH 128

struct cmp_hints_pending {
	unsigned long ip;
	unsigned long val;
	unsigned int size;
};

unsigned int cmp_hints_flush_pending(struct cmp_hint_pool *pool,
				     unsigned int nr, bool do32,
				     const struct cmp_hints_pending *batch,
				     unsigned int n);

/*
 * Per-child A/B stamp for the cmp-hints live-pick policy.  Arm B
 * routes the uniform draw through cmp_hint_weighted_pick() below.
 * Definition + stamp state live in cmp_hints/get.c; the field
 * consumer in cmp_hints/field.c also gates its LIVE-arm pick through
 * the same stamp so both consumers stay in the same cohort.
 */
bool cmp_hint_livepick_arm_b_active(void);

/*
 * Weighted draw over cmp_hint_entry.wins / .misses.  Definition in
 * cmp_hints/get.c; called from the per-syscall picker (get.c) and
 * from the field-scoped picker (cmp_hints/field.c) when
 * cmp_hint_livepick_arm_b_active() is true.  count is the
 * corruption-gated snapshot; entries is the pool's entries[] array.
 */
unsigned int cmp_hint_weighted_pick(struct cmp_hint_entry *entries,
				    unsigned int count);

/*
 * Post-transform tier verdict for cmp_try_get_recent_tier().
 * Definition + callers all live in cmp_hints/get.c today but the
 * enum is declared here so a future consumer can pattern-match the
 * tier outcome without pulling in the whole picker header block.
 */
enum cmp_tier_result {
	CMP_TIER_MISS = 0,
	CMP_TIER_SERVED,
	CMP_TIER_REJECTED,
};

/*
 * Per-use-case output transform applied after the pool entry is
 * picked.  Definition in cmp_hints/collect.c; the picker
 * (cmp_hints/get.c) and the field consumer (cmp_hints/field.c) both
 * route their served value through it before writing *out.
 */
unsigned long cmp_hint_apply_transform(unsigned long c,
				       enum cmp_hint_use use,
				       unsigned long old);

/*
 * Push one entry onto the per-child SHADOW consume stash.
 * Definition in cmp_hints/collect.c; every successful pick in
 * cmp_hints/get.c (per-syscall and recent tiers) and cmp_hints/field.c
 * (field-scoped LIVE arm) calls it so the dispatch-tail feedback
 * drain in cmp_hints/credit.c has a per-pull record to score
 * against.
 */
void cmp_hints_stash_consumed(unsigned int nr, bool do32,
			      enum cmp_hint_pool_kind pool_kind,
			      enum cmp_hint_callsite callsite,
			      unsigned long cmp_ip, unsigned long value,
			      unsigned int size, enum cmp_hint_use use,
			      unsigned int arg_idx,
			      unsigned int field_idx,
			      const struct struct_desc *desc,
			      bool served_from_recent,
			      uint8_t age_bucket,
			      bool hyp_injected,
			      bool served_from_shared);

/*
 * SHADOW typed-hypothesis consume credit.  Called from
 * cmp_hints_stash_consumed() (collect.c) on every push so the typed
 * denominator tracks the per-pool denominator.  Definition in
 * cmp_hints/hyp.c.
 */
void cmp_hyp_credit_consume(unsigned int nr, bool do32,
			    unsigned long cmp_ip, unsigned long value,
			    unsigned int size);

/*
 * SHADOW would-pick resolver.  Invoked on every successful raw-pool
 * pick from cmp_hints/get.c so the would-pick / would-miss /
 * would-value-differs counters in kcov_shm stay comparable across
 * runs.  Definition in cmp_hints/hyp.c.
 */
void cmp_hyp_would_pick(unsigned int nr, bool do32,
			unsigned long cmp_ip, unsigned int size,
			unsigned long live_value);

/*
 * Fleet-wide shared cmp_ip tier insert.  Called under the per-nr
 * pool->lock from cmp_hints/pool.c immediately after every
 * pool_add_locked() SUCCESS (fresh insert / evict-replace); the tier
 * mirrors the (cmp_ip, value, size) tuple that just landed in a per-
 * nr pool so a follow-up cold per-nr lookup can eventually warm-
 * start from constants ANY sibling syscall already learned at the
 * same kernel check.  nr is folded into the bucket's seen_nrs bitmap
 * so the entry-path filter (distinct_nr_count >
 * CMP_SHARED_TIER_ENTRY_PATH_NR_MAX) can latch an IP that fires
 * under too many syscalls to be a useful warm-start seed.
 * Definition in cmp_hints/pool.c.
 *
 * Bounded work per call: hash lookup + up to CMP_SHARED_TIER_PROBE_MAX
 * bucket probes + up to CMP_SHARED_TIER_VALUES value-slot scans; no
 * allocation, no RNG.  Silently drops on shm==NULL, cmp_ip==0
 * (sentinel-guard for the occupancy check), or probe exhaustion --
 * the tier is fallback/warm-start ONLY, so drops are the same shape
 * as the per-nr LRU eviction and never a correctness issue.
 */
void cmp_shared_tier_insert(unsigned int nr, unsigned long cmp_ip,
			    unsigned long value, unsigned int size);

/*
 * Fleet-wide shared cmp_ip tier warm-load populate.  Called once from
 * cmp_hints_load_file() after the per-nr pools have been restored
 * from the on-disk snapshot; walks pools[][] and unions each live
 * (cmp_ip, value, size) tuple into the shared tier via
 * cmp_shared_tier_insert().  Idempotent under multiple calls (the
 * tier's dedup collapses duplicate contributions).  Definition in
 * cmp_hints/pool.c.
 */
void cmp_shared_tier_populate_from_pools(void);

/*
 * SHADOW probe fired from cmp_hints/get.c when a per-nr lookup would
 * miss (durable pool empty on the (nr, do32) slot AND the recent-tier
 * pre-pass did not serve).  Bumps cmp_shared_tier_shadow_warmstart_
 * eligible when the shared tier has ANY non-entry-path IP that could
 * seed the cold per-nr pool.  Value-neutral: does NOT read or return
 * a shared-tier value, does NOT consume RNG, does NOT change what
 * try_get returns.  Definition in cmp_hints/pool.c.
 *
 * OFF-mode short-circuits BEFORE any shared-tier / counter access so
 * a default build's get-path is bit-for-bit identical to a pre-tier
 * baseline.
 */
void cmp_shared_tier_shadow_probe_cold_miss(void);

/*
 * COMBINED-mode QUARANTINED live serve fired from cmp_hints/get.c on
 * a per-nr cold miss, immediately after cmp_shared_tier_shadow_probe_
 * cold_miss() has recorded the eligibility.  Elects an occupied,
 * non-entry-path-excluded shared-tier bucket at random under the
 * shared_tier_lock and returns one of its (value, size) pairs plus
 * the bucket's cmp_ip via *out / *out_size on true; leaves *out /
 * *out_size untouched on false so the caller's fall-through miss
 * path stays unchanged.  Applies cmp_hint_apply_transform() and the
 * caller's cmp_accept_range before the commit so a rejected served
 * value returns false and does NOT bump cmp_shared_tier_serves.
 *
 * On a successful serve the stash entry is stamped served_from_
 * shared=1; the credit drain then routes the PC outcome to
 * cmp_hint_tier_shared_wins / _misses ONLY and skips every native
 * pool per-entry / by-pool / by-tier / by-age credit (the
 * quarantine invariant that gates a future promotion decision off
 * this shared-tier bootstrap).
 *
 * Gated on cmp_shared_tier_mode == CMP_SHARED_TIER_MODE_COMBINED
 * AND ONE_IN(CMP_SHARED_TIER_SERVE_DICE); OFF and SHADOW_ONLY
 * short-circuit to false without touching the tier or the caller
 * out-params.  Definition in cmp_hints/pool.c.
 */
bool cmp_shared_tier_try_serve_cold_miss(unsigned int nr, bool do32,
					 enum cmp_hint_use use,
					 unsigned long old,
					 const struct cmp_accept_range *accept,
					 enum cmp_hint_callsite callsite,
					 unsigned long *out,
					 unsigned int *out_size);

/*
 * LIVE typed-hypothesis inject arm.  Called from cmp_hints/get.c on
 * durable-tier picks whose caller opted in (allow_hyp_inject).  On a
 * gate + resolver + derive triple-hit the raw pool value is replaced
 * by a hypothesis-derived value; the *out_kind / *out_gate_fired
 * out-params let the caller book the accept-gated denominator +
 * per-kind partition at the commit point.  Definition in
 * cmp_hints/hyp.c.
 *
 * arg_idx is the caller's syscall argnum (1..6) threaded through from
 * cmp_hints_try_get_ex for the placement-proof observability contract
 * (typed_inject_fill_slot_hist[]).  Value-neutral inside this helper:
 * the counter is bumped by the caller at the accept-gated commit
 * point, not here, and the helper adds no rnd_*() draw / no derived
 * value change tied to arg_idx.  Preserving the full plumbing keeps
 * the fill-slot contract visible at the site the derived value is
 * produced.
 *
 * callsite is the argtype-handler classification threaded through from
 * cmp_hints_try_get_ex.  Value-neutral for the LIVE inject path (does
 * not gate the raw pool / typed hypothesis pick or derive output).
 * Consumed only by the SHADOW pow2 / alignment derive measurement in
 * cmp_hyp_derive_value(), which filters to size / offset-class
 * callsites (ARG_RANGE, ARG_STRUCT_SIZE) so the pow2 lane's would-fire
 * / would-win counters are not polluted by flag- or enum-typed picks
 * that overlap the existing EXACT / ENUM_FAMILY lanes.
 */
bool cmp_hyp_try_live_inject(unsigned int nr, bool do32,
			     unsigned long cmp_ip, unsigned int size,
			     unsigned int arg_idx,
			     enum cmp_hint_callsite callsite,
			     unsigned long *out,
			     uint8_t *out_kind,
			     bool *out_gate_fired);

#endif /* _CMP_HINTS_INTERNAL_H */
