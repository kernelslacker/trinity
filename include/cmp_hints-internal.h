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
 */
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
			      unsigned long cmp_ip, unsigned long value,
			      unsigned int size, enum cmp_hint_use use,
			      unsigned int arg_idx,
			      unsigned int field_idx,
			      const struct struct_desc *desc,
			      bool served_from_recent,
			      uint8_t age_bucket,
			      bool hyp_injected);

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
 * LIVE typed-hypothesis inject arm.  Called from cmp_hints/get.c on
 * durable-tier picks whose caller opted in (allow_hyp_inject).  On a
 * gate + resolver + derive triple-hit the raw pool value is replaced
 * by a hypothesis-derived value; the *out_kind / *out_gate_fired
 * out-params let the caller book the accept-gated denominator +
 * per-kind partition at the commit point.  Definition in
 * cmp_hints/hyp.c.
 */
bool cmp_hyp_try_live_inject(unsigned int nr, bool do32,
			     unsigned long cmp_ip, unsigned int size,
			     unsigned long *out,
			     uint8_t *out_kind,
			     bool *out_gate_fired);

#endif /* _CMP_HINTS_INTERNAL_H */
