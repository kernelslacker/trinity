/*
 * Per-syscall cmp-hint pool primitives.
 *
 * Holds the pool lock helpers, the wild-write corruption gate, the
 * dedup + LRU-eviction insert (pool_add_locked), the per-child seen
 * bloom, the recent-ring insert (both durable + childop quarantine
 * lanes), and the batched flush that the collect cluster drains its
 * per-record pending buffer through.
 */

#include <stdint.h>
#include <string.h>

#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "kcov.h"
#include "locks.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "tables.h"

void pool_lock(struct cmp_hint_pool *pool)
{
	if (cmp_hints_shm != NULL)
		__atomic_fetch_add(&cmp_hints_shm->held_count, 1,
				__ATOMIC_RELAXED);
	lock(&pool->lock);
}

void pool_unlock(struct cmp_hint_pool *pool)
{
	unlock(&pool->lock);
	if (cmp_hints_shm != NULL)
		__atomic_sub_fetch(&cmp_hints_shm->held_count, 1,
				__ATOMIC_RELAXED);
}

/*
 * Wild-write gate for the cmp_hints SHM pool.  Called by every reader
 * (try_get lockless, pool_add_locked under lock) immediately after the
 * count load.  Bumps three independent kcov_shm counters so the
 * post-mortem can attribute corruption to whichever channel hit:
 *
 *   - cmp_hints_count_oob:                pool->count exceeds the
 *                                         16-slot cap, the only sign
 *                                         visible from the read path
 *                                         itself.
 *   - cmp_hints_canary_lock_post_corrupt: the sentinel between lock
 *                                         and count has been
 *                                         overwritten -- a wide write
 *                                         landed in the lock/count
 *                                         seam.
 *   - cmp_hints_canary_pre_corrupt:       the sentinel between
 *                                         last_used_stamp and
 *                                         entries[] has been
 *                                         overwritten -- write
 *                                         reached the pool from the
 *                                         header side.
 *   - cmp_hints_canary_post_corrupt:      the sentinel after entries[]
 *                                         has been overwritten --
 *                                         write reached the pool
 *                                         from the tail side.
 *
 * A narrow stomp that lands exactly on count (or exactly on any
 * single header field) trips ONLY count_oob; the canaries flank the
 * data but cannot detect a write that fits entirely between them.
 * Non-zero canary deltas narrow the stomp's width and direction --
 * useful for forensics, not load-bearing for the corruption-present
 * decision.  Canary loads are gated on the count check so the
 * steady-state cost is one compare-against-16; the canary cache
 * lines are only touched once a stomp has already occurred.  Returns
 * true when corruption is present so callers can treat the pool as
 * advisory-empty.
 *
 * Per-pool latch (pool->corrupted) one-shots the counter bumps: the
 * first observation records the channel, every subsequent call
 * returns true from the latch check and skips both the count
 * comparison and the canary probes.  Without this, the batch loop in
 * cmp_hints_flush_pending would multiply a single stomp event by up
 * to CMP_HINTS_PENDING_BATCH bumps per cmp_hints_collect call and
 * the count_oob counter would track "exposures" instead of "events".
 */
bool cmp_hints_pool_corrupted(struct cmp_hint_pool *pool,
			      unsigned int observed_count)
{
	if (__atomic_load_n(&pool->corrupted, __ATOMIC_RELAXED))
		return true;
	if (observed_count <= CMP_HINTS_PER_SYSCALL)
		return false;
	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->hints_canary.cmp_hints_count_oob, 1UL,
				   __ATOMIC_RELAXED);
		if (pool->canary_lock_post != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->hints_canary.cmp_hints_canary_lock_post_corrupt,
					   1UL, __ATOMIC_RELAXED);
		if (pool->canary_pre != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->hints_canary.cmp_hints_canary_pre_corrupt,
					   1UL, __ATOMIC_RELAXED);
		if (pool->canary_post != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->hints_canary.cmp_hints_canary_post_corrupt,
					   1UL, __ATOMIC_RELAXED);
	}
	__atomic_store_n(&pool->corrupted, true, __ATOMIC_RELAXED);
	return true;
}

/*
 * Clamp wrapper for readers that need pool->count for accounting but
 * do NOT index into entries[] (stats accumulators, strategy classifier).
 * Returns 0 on a stomped pool so accounting code doesn't fold garbage
 * counts into totals.  Side-effects identical to cmp_hints_pool_corrupted:
 * first observation of an OOB count records the channel via the kcov_shm
 * counters and latches pool->corrupted, so these readers participate in
 * the same one-shot accounting as the index-into-entries readers.
 *
 * Also closes a TOCTOU on the existing call sites that read .count
 * twice in quick succession ('if (count > 0) total += count;'): a
 * single atomic load drives both the test and the value used.
 */
unsigned int cmp_hints_pool_safe_count(struct cmp_hint_pool *pool)
{
	unsigned int count = __atomic_load_n(&pool->count, __ATOMIC_RELAXED);

	if (cmp_hints_pool_corrupted(pool, count))
		return 0;
	return count;
}

/*
 * cmp_hint_age_bucket() definition moved to include/cmp_hints-internal.h
 * so cmp_hints/get.c and cmp_hints/field.c both see it inline.  The
 * static assert stays here (in the pool cluster) alongside the kcov_shm
 * histogram it guards.
 */
_Static_assert(CMP_HINT_AGE_BUCKETS == 7U,
	       "cmp_hint_age_bucket() arms must match CMP_HINT_AGE_BUCKETS");

/*
 * Insert (cmp_ip, val, size) into the entries[] array.  Dedups via linear
 * scan on the full (cmp_ip, value, size) key.  When the pool is full,
 * evicts the entry with the smallest last_used (least-recently-inserted)
 * to make room.  Duplicate hits refresh last_used so an actively-observed
 * constant doesn't get evicted by transient long-tail noise.  Caller must
 * hold pool->lock.
 *
 * pool->generation is bumped ONLY on real content changes (fresh insert
 * or evict-replace), never on dedup-refresh.  That keeps the
 * cmp_hints_total_generation() snapshot dirty-bit honest: a saturated
 * pool whose hot tuples keep dedup-refreshing produces no generation
 * delta and therefore no redundant snapshot save.  The LRU clock that
 * stamps each entry's last_used uses a separate per-pool counter
 * (pool->last_used_stamp) which advances on every call — including
 * dedup-refresh — so the eviction policy is unchanged from before this
 * split: an actively-observed tuple still gets its stamp refreshed and
 * is still the last thing the evictor will pick.
 */
static bool pool_add_locked(struct cmp_hint_pool *pool,
			    unsigned int nr,
			    unsigned long cmp_ip,
			    unsigned long val,
			    unsigned int size)
{
	unsigned int i, count = pool->count;
	uint64_t stamp;
	unsigned int victim;
	uint64_t oldest;

	/* SHM stomp from a fuzzed syscall arg has scribbled count past the
	 * 16-slot cap; the dedup loop below would walk off entries[].  Bail
	 * before mutating anything (including last_used_stamp). */
	if (cmp_hints_pool_corrupted(pool, count))
		return false;

	stamp = ++pool->last_used_stamp;

	for (i = 0; i < count; i++) {
		struct cmp_hint_entry *e = &pool->entries[i];

		if (e->value == val && e->cmp_ip == cmp_ip && e->size == size) {
			e->last_used = stamp;
			if (kcov_shm != NULL)
				__atomic_fetch_add(&kcov_shm->hint_reject.cmp_hints_save_reject_dup,
						   1UL, __ATOMIC_RELAXED);
			return false;
		}
	}

	if (count < CMP_HINTS_PER_SYSCALL) {
		struct cmp_hint_entry *e = &pool->entries[count];

		e->value = val;
		e->cmp_ip = cmp_ip;
		e->size = size;
		/* SHADOW feedback score starts at zero for a freshly inserted
		 * tuple.  Dedup-refresh above keeps the existing score (same
		 * tuple, same identity); only this fresh-insert and the
		 * evict-replace below reset. */
		e->wins = 0;
		e->misses = 0;
		e->last_used = stamp;
		__atomic_fetch_add(&pool->generation, 1, __ATOMIC_RELAXED);
		/*
		 * RELEASE-store count so a lockless reader in cmp_hints_try_get
		 * that observes the new count is guaranteed to also see the
		 * entries[] store above.
		 */
		__atomic_store_n(&pool->count, count + 1, __ATOMIC_RELEASE);
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->hints_flat.cmp_hints_unique_inserts,
					   1UL, __ATOMIC_RELAXED);
		return true;
	}

	victim = 0;
	oldest = pool->entries[0].last_used;
	for (i = 1; i < CMP_HINTS_PER_SYSCALL; i++) {
		if (pool->entries[i].last_used < oldest) {
			oldest = pool->entries[i].last_used;
			victim = i;
		}
	}
	pool->entries[victim].value = val;
	pool->entries[victim].cmp_ip = cmp_ip;
	pool->entries[victim].size = size;
	/* Evict-replace: zero the SHADOW score so the displaced tuple's
	 * history does not bleed into the new identity that now lives in
	 * this slot. */
	pool->entries[victim].wins = 0;
	pool->entries[victim].misses = 0;
	pool->entries[victim].last_used = stamp;
	__atomic_fetch_add(&pool->generation, 1, __ATOMIC_RELAXED);
	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->hints_flat.cmp_hints_unique_inserts, 1UL,
				   __ATOMIC_RELAXED);
		/* Evict-replace pressure: a tuple displaced an older one
		 * because the per-syscall cap was full.  The new entry won
		 * the slot (counted via cmp_hints_unique_inserts above) and
		 * the evicted entry is the silent loser; the cap counter
		 * tracks displacement events so a saturated pool is
		 * directly visible as cap > unique_inserts_delta over a
		 * window once the per-syscall pool tops out. */
		__atomic_fetch_add(&kcov_shm->hint_reject.cmp_hints_save_reject_cap, 1UL,
				   __ATOMIC_RELAXED);
		/* Per-syscall partition of the cap-pressure counter.
		 * Sibling of per_syscall_cmp_inserts[nr] (bumped above
		 * via cmp_hints_unique_inserts and again at the
		 * cmp_hints_collect tail).  nr is gated to MAX_NR_SYSCALL
		 * at cmp_hints_collect() entry; this insert path is only
		 * ever reached through cmp_hints_flush_pending which
		 * threads the same nr through unchanged, so the index is
		 * in-bounds. */
		if (nr < MAX_NR_SYSCALL)
			__atomic_fetch_add(&kcov_shm->hint_tier.per_syscall_cmp_reject_cap[nr],
					   1UL, __ATOMIC_RELAXED);
	}
	return true;
}

/*
 * Per-child seen-bloom hashes over the (cmp_ip, val, size) tuple.  Two
 * independent splitmix64-style mixes -- the same shape the cmp_novelty
 * bloom in strategy.c uses, kept local so the two hash families are
 * free to drift if one turns out to need a different mixing constant
 * for the load it actually sees.  Indices are masked to
 * CMP_HINTS_BLOOM_MASK so the bloom width can change without touching
 * the hashes.
 */
static inline uint32_t cmp_hints_bloom_h1(unsigned long ip, unsigned long val,
					  unsigned int size)
{
	uint64_t x = (uint64_t)ip
		   ^ ((uint64_t)val * 0x9e3779b97f4a7c15ULL)
		   ^ ((uint64_t)size << 13);

	x ^= x >> 32;
	x *= 0xbf58476d1ce4e5b9ULL;
	x ^= x >> 27;
	return (uint32_t)(x & CMP_HINTS_BLOOM_MASK);
}

static inline uint32_t cmp_hints_bloom_h2(unsigned long ip, unsigned long val,
					  unsigned int size)
{
	uint64_t x = (uint64_t)val
		   ^ ((uint64_t)ip * 0x94d049bb133111ebULL)
		   ^ ((uint64_t)size * 0xff51afd7ed558ccdULL);

	x ^= x >> 30;
	x *= 0xc4ceb9fe1a85ec53ULL;
	x ^= x >> 31;
	return (uint32_t)(x & CMP_HINTS_BLOOM_MASK);
}

/*
 * Test-and-set both bloom bits for the tuple.  Returns true when both
 * bits were already set -- the tuple has been seen within the current
 * bloom window, so the caller can skip pool_add_locked.  A miss on
 * either bit returns false AND leaves both bits set, so the next
 * encounter with the same tuple hits.
 */
bool cmp_hints_bloom_check_and_set(struct cmp_hints_bloom *b,
				   unsigned long ip,
				   unsigned long val,
				   unsigned int size)
{
	uint32_t i1 = cmp_hints_bloom_h1(ip, val, size);
	uint32_t i2 = cmp_hints_bloom_h2(ip, val, size);
	uint8_t m1 = (uint8_t)(1U << (i1 & 7));
	uint8_t m2 = (uint8_t)(1U << (i2 & 7));
	uint8_t *p1 = &b->bits[i1 >> 3];
	uint8_t *p2 = &b->bits[i2 >> 3];
	bool seen = ((*p1 & m1) != 0) && ((*p2 & m2) != 0);

	*p1 |= m1;
	*p2 |= m2;
	return seen;
}

/*
 * Read-only bloom probe.  Same hash pair as check_and_set above, but
 * does NOT mutate the filter -- returns true only when both bits are
 * already set, false otherwise.  For shadow readouts that need to ask
 * "would this tuple have been treated as fresh?" without stamping bits
 * the natural (cmp_ip, arg1, size) ingress does not.
 */
bool cmp_hints_bloom_probe(const struct cmp_hints_bloom *b,
			   unsigned long ip,
			   unsigned long val,
			   unsigned int size)
{
	uint32_t i1 = cmp_hints_bloom_h1(ip, val, size);
	uint32_t i2 = cmp_hints_bloom_h2(ip, val, size);
	uint8_t m1 = (uint8_t)(1U << (i1 & 7));
	uint8_t m2 = (uint8_t)(1U << (i2 & 7));

	return ((b->bits[i1 >> 3] & m1) != 0) &&
	       ((b->bits[i2 >> 3] & m2) != 0);
}

/*
 * CMP_HINTS_PENDING_BATCH moved to include/cmp_hints-internal.h --
 * cmp_hints/collect.c allocates the stack batch and cmp_hints/pool.c
 * drains it, so both sides need the same size.
 *
 * struct cmp_hints_pending moved to include/cmp_hints-internal.h so
 * cmp_hints/collect.c can build the batch and cmp_hints/pool.c can
 * drain it against the same type.
 */

/*
 * Recent-ring insert.  Called for every
 * pool_add_locked() return-true (fresh insert or evict-replace) under
 * the durable pool's lock, so the only writer at any instant is the
 * caller already holding pool->lock above; recent_pools[] needs no
 * lock of its own.  Lockless readers in cmp_hints_try_get_ex tolerate
 * a torn (cmp_ip, value, size) triplet the same way the durable pool's
 * lockless reader does -- hints are advisory.
 *
 * Ring write: overwrite the head slot, advance head modulo the cap.
 * Count grows up to CMP_RECENT_PER_SYSCALL and then sticks; an insert
 * over a populated slot bumps cmp_recent_evicts so the saturation
 * point is observable.  No dedup deliberately: "recent" semantics aren't
 * diluted by collapsing a tuple the kernel saw twice into one slot.
 */
static void cmp_recent_insert(unsigned int nr, bool do32,
			      unsigned long cmp_ip, unsigned long val,
			      unsigned int size)
{
	struct cmp_recent_pool *rp;
	unsigned int head;
	unsigned int count;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;

	rp = &cmp_hints_shm->recent_pools[nr][do32 ? 1 : 0];
	head = rp->head;
	if (head >= CMP_RECENT_PER_SYSCALL)
		head = 0;	/* defensive: a stomp on head would index OOB */
	count = rp->count;

	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->cmp_recent.cmp_recent_inserts, 1UL,
				   __ATOMIC_RELAXED);
		if (count >= CMP_RECENT_PER_SYSCALL)
			__atomic_fetch_add(&kcov_shm->cmp_recent.cmp_recent_evicts, 1UL,
					   __ATOMIC_RELAXED);
	}

	rp->entries[head].value = val;
	rp->entries[head].cmp_ip = cmp_ip;
	rp->entries[head].size = size;
	rp->entries[head].pad = 0;

	head = (head + 1U) % CMP_RECENT_PER_SYSCALL;
	__atomic_store_n(&rp->head, head, __ATOMIC_RELAXED);
	if (count < CMP_RECENT_PER_SYSCALL)
		__atomic_store_n(&rp->count, count + 1U, __ATOMIC_RELEASE);
}

/*
 * Childop quarantine-lane insert.  Mirrors cmp_recent_insert() above
 * but writes to cmp_hints_shared.childop_recent_pools[nr][do32] --
 * the source-tagged, non-persisted, non-LRU-displacing lane that
 * the §3.2 trinity_cmp_syscall harvest feeds when
 * --childop-cmp-harvest=on.
 *
 * Single-writer per (nr, do32): every caller runs inside a
 * trinity_cmp_syscall() under a kcov_cmp_bracket on a CMP-mode
 * child, and a CMP-mode child only ever holds one bracket at a
 * time, so the head/count writes need no lock.  Lockless readers
 * in the eventual consume side will tolerate a torn (cmp_ip, val,
 * size) triplet the same way cmp_hints_try_get_ex() tolerates one
 * against recent_pools[] today.
 *
 * Pool-insert / pool-evict bumps land in kcov_shm under the same
 * per-nr keying the rest of the childop_cmp_* shadow counters use,
 * so the eviction-pressure signal the §3.1 promotion gate consumes
 * is observable per-nr from day one.
 */
void cmp_hints_childop_insert(unsigned int nr, bool do32,
			      unsigned long cmp_ip, unsigned long val,
			      unsigned int size)
{
	struct cmp_recent_pool *rp;
	unsigned int head;
	unsigned int count;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;

	rp = &cmp_hints_shm->childop_recent_pools[nr][do32 ? 1 : 0];
	head = rp->head;
	if (head >= CMP_RECENT_PER_SYSCALL)
		head = 0;	/* defensive: stomp on head indexed OOB */
	count = rp->count;

	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->childop_cmp_pool_inserts[nr],
				   1UL, __ATOMIC_RELAXED);
		if (count >= CMP_RECENT_PER_SYSCALL)
			__atomic_fetch_add(&kcov_shm->childop_cmp_pool_evicts[nr],
					   1UL, __ATOMIC_RELAXED);
	}

	rp->entries[head].value = val;
	rp->entries[head].cmp_ip = cmp_ip;
	rp->entries[head].size = size;
	rp->entries[head].pad = 0;

	head = (head + 1U) % CMP_RECENT_PER_SYSCALL;
	__atomic_store_n(&rp->head, head, __ATOMIC_RELAXED);
	if (count < CMP_RECENT_PER_SYSCALL)
		__atomic_store_n(&rp->count, count + 1U, __ATOMIC_RELEASE);
}

unsigned int cmp_hints_flush_pending(struct cmp_hint_pool *pool,
				     unsigned int nr, bool do32,
				     const struct cmp_hints_pending *batch,
				     unsigned int n)
{
	unsigned int j;
	unsigned int inserted = 0;

	if (n == 0)
		return 0;
	/* Pre-lock fast path for already-latched-corrupted pools.  Each
	 * pool_add_locked() below routes count through cmp_hints_pool_corrupted()
	 * and bails before any state mutation (including last_used_stamp)
	 * once the latch is set, so the lock acquire + N-iteration batch
	 * walk yields zero inserts and zero side effects on a latched pool
	 * -- pure overhead.  The latched-corrupted branch in
	 * cmp_hints_pool_corrupted() is itself side-effect free (no
	 * counter bumps, no re-latch, no canary probes) by design, so
	 * skipping the walk does not lose any per-record accounting that
	 * the in-walk check would have produced. */
	if (__atomic_load_n(&pool->corrupted, __ATOMIC_RELAXED))
		return 0;
	pool_lock(pool);
	for (j = 0; j < n; j++) {
		if (pool_add_locked(pool, nr, batch[j].ip, batch[j].val,
				    batch[j].size)) {
			inserted++;
			/* Mirror every durable content change into the
			 * run-local recent ring.  Under pool->lock so the
			 * recent insert has the same single-writer guarantee
			 * the durable insert has -- the only place that
			 * writes recent_pools[nr][do32] is this exact path. */
			cmp_recent_insert(nr, do32, batch[j].ip, batch[j].val,
					  batch[j].size);
			/* SHADOW typed-hypothesis inference fed every
			 * fresh (nr, do32, ip, val, size) tuple under the
			 * same lock window, so the hyp_pools writes
			 * serialise per-(nr, do32) without a second lock
			 * and no second walk over the trace buffer. */
			cmp_hyp_observe(nr, do32, batch[j].ip, batch[j].val,
					batch[j].size);
			/* Mirror the same fresh content change into the
			 * fleet-wide shared cmp_ip tier so a cold per-nr
			 * pool can eventually warm-start from constants
			 * ANY sibling syscall learned at the same kernel
			 * check.  Acquires the tier's own global lock
			 * internally -- the per-nr pool->lock is held
			 * here, so the two locks nest strictly in this
			 * order (pool->lock outer, shared_tier_lock
			 * inner) and no other caller acquires the tier
			 * lock while holding a per-nr pool lock. */
			cmp_shared_tier_insert(nr, batch[j].ip, batch[j].val,
					       batch[j].size);
		}
	}
	pool_unlock(pool);
	return inserted;
}

/*
 * Fleet-wide shared cmp_ip tier.
 *
 * See the CMP_SHARED_TIER_* / struct cmp_shared_tier_bucket comments in
 * include/cmp_hints.h for the tier's data model, entry-path filter, and
 * NOT-persisted contract.  All state lives inside cmp_hints_shm; this
 * cluster owns the hash + probe + insert primitives plus the warm-load
 * populate walk.
 *
 * Hot-path cost: insert is called from cmp_hints_flush_pending only on a
 * pool_add_locked() success (fresh insert / evict-replace), so the per-
 * record rate is capped by the bloom + LRU-eviction discipline that
 * already bounds the durable pool.  Steady-state cost is one hash + up
 * to CMP_SHARED_TIER_PROBE_MAX bucket probes under the tier's global
 * lock; the bucket-side work is a linear scan of at most
 * CMP_SHARED_TIER_VALUES value slots and one bit test/set in
 * seen_nrs[].  No allocation, no RNG, no cross-nr atomic contention
 * beyond the single shared_tier_lock.
 */
static inline uint32_t cmp_shared_tier_hash(unsigned long cmp_ip)
{
	/* splitmix64-shape mix on the canonical cmp_ip.  Same finalising
	 * constants as cmp_hints_bloom_h1 above so the two hash families
	 * share a common shape, but keyed off cmp_ip alone (the shared
	 * tier's identity is a single kernel comparison site, not a
	 * (cmp_ip, value, size) tuple). */
	uint64_t x = (uint64_t)cmp_ip;

	x ^= x >> 30;
	x *= 0xbf58476d1ce4e5b9ULL;
	x ^= x >> 27;
	x *= 0x94d049bb133111ebULL;
	x ^= x >> 31;
	return (uint32_t)(x & (CMP_SHARED_TIER_IPS - 1U));
}

/* Set bit `nr` in the bucket's seen_nrs[] membership bitmap.  Returns
 * true when the bit was previously unset (this nr is a NEW contributor
 * for the bucket, so the caller should bump distinct_nr_count).  Caller
 * holds shared_tier_lock. */
static inline bool cmp_shared_tier_mark_nr(struct cmp_shared_tier_bucket *b,
					   unsigned int nr)
{
	unsigned int byte = nr >> 3;
	uint8_t mask = (uint8_t)(1U << (nr & 7U));

	if (byte >= sizeof(b->seen_nrs))
		return false;	/* out of range; caller pre-gates but be safe */
	if ((b->seen_nrs[byte] & mask) != 0)
		return false;
	b->seen_nrs[byte] |= mask;
	return true;
}

/* Value-slot upsert under the tier's global lock.  Returns
 *   > 0  on a fresh append or dedup hit (the value is in the bucket
 *        after the call);
 *   == 0 on a value-slot overflow (bucket saturated at
 *        CMP_SHARED_TIER_VALUES; drop silently -- tier is fallback,
 *        not authoritative).
 * *was_present receives true when the (value, size) pair was already
 * in the bucket before the call, false on a fresh append (or on
 * overflow, though the flag is unused in that arm). */
static bool cmp_shared_tier_upsert_value(struct cmp_shared_tier_bucket *b,
					 unsigned long value, unsigned int size,
					 bool *was_present)
{
	unsigned int i;
	unsigned int cap = b->value_count;

	if (cap > CMP_SHARED_TIER_VALUES)
		cap = CMP_SHARED_TIER_VALUES;
	for (i = 0; i < cap; i++) {
		if (b->values[i].value == value &&
		    b->values[i].size == size) {
			*was_present = true;
			return true;
		}
	}
	*was_present = false;
	if (b->value_count >= CMP_SHARED_TIER_VALUES)
		return false;
	b->values[b->value_count].value = value;
	b->values[b->value_count].size = size;
	b->values[b->value_count].pad = 0;
	b->value_count++;
	return true;
}

void cmp_shared_tier_insert(unsigned int nr, unsigned long cmp_ip,
			    unsigned long value, unsigned int size)
{
	uint32_t start;
	unsigned int probe;

	/* OFF-mode short-circuit BEFORE any shared-tier access so a
	 * default build is bit-for-bit identical to a pre-shared-tier
	 * baseline: no shm reads, no lock, no counter bump.  Read the
	 * mode RELAXED -- the mode is a startup-time knob, never flipped
	 * mid-run, so a racing load can never observe a partial store. */
	if (__atomic_load_n(&cmp_shared_tier_mode, __ATOMIC_RELAXED) ==
	    CMP_SHARED_TIER_MODE_OFF)
		return;
	if (cmp_hints_shm == NULL)
		return;
	/* Sentinel guard: cmp_ip == 0 is used as the "bucket unclaimed"
	 * marker by callers that want to peek without a lock; drop the
	 * (exceedingly rare) canonical-cmp_ip == 0 case rather than mix
	 * it into the shared tier's occupancy signal.  Same shape as the
	 * per-nr corruption gate: cheap check up front, tier is
	 * advisory. */
	if (cmp_ip == 0)
		return;
	if (nr >= MAX_NR_SYSCALL)
		return;

	start = cmp_shared_tier_hash(cmp_ip);

	lock(&cmp_hints_shm->shared_tier_lock);
	for (probe = 0; probe < CMP_SHARED_TIER_PROBE_MAX; probe++) {
		uint32_t idx = (start + probe) & (CMP_SHARED_TIER_IPS - 1U);
		struct cmp_shared_tier_bucket *b =
			&cmp_hints_shm->shared_tier[idx];
		bool was_present = false;
		bool value_accepted;

		if (b->occupied == 0) {
			/* Claim.  Populate key + first value + nr membership
			 * before publishing occupied, so a lockless reader
			 * that observes occupied=1 via ACQUIRE-load sees a
			 * fully populated bucket. */
			b->cmp_ip = cmp_ip;
			b->values[0].value = value;
			b->values[0].size = size;
			b->values[0].pad = 0;
			b->value_count = 1;
			(void)cmp_shared_tier_mark_nr(b, nr);
			b->distinct_nr_count = 1;
			b->entry_path_excluded = 0;
			__atomic_store_n(&b->occupied, (uint8_t)1,
					 __ATOMIC_RELEASE);
			unlock(&cmp_hints_shm->shared_tier_lock);
			if (kcov_shm != NULL) {
				__atomic_fetch_add(&kcov_shm->cmp_shared_tier_ips,
						   1UL, __ATOMIC_RELAXED);
				__atomic_fetch_add(&kcov_shm->cmp_shared_tier_entries,
						   1UL, __ATOMIC_RELAXED);
			}
			return;
		}
		if (b->cmp_ip == cmp_ip) {
			bool new_nr = cmp_shared_tier_mark_nr(b, nr);
			bool now_excluded = false;

			if (new_nr) {
				b->distinct_nr_count++;
				if (b->distinct_nr_count >
					CMP_SHARED_TIER_ENTRY_PATH_NR_MAX &&
				    b->entry_path_excluded == 0) {
					b->entry_path_excluded = 1;
					now_excluded = true;
				}
			}
			value_accepted = cmp_shared_tier_upsert_value(b, value,
								      size,
								      &was_present);
			unlock(&cmp_hints_shm->shared_tier_lock);
			if (kcov_shm != NULL) {
				if (value_accepted && !was_present)
					__atomic_fetch_add(&kcov_shm->cmp_shared_tier_entries,
							   1UL,
							   __ATOMIC_RELAXED);
				/* Cross-nr redundant learn: THIS nr is new to
				 * the bucket AND the (value, size) was already
				 * present from a prior contributor.  The tier
				 * could have SUPPLIED this constant to us via
				 * warm-start instead of us learning it
				 * ourselves -- that is the SHADOW dedup signal
				 * the follow-up live wire-up will exploit. */
				if (new_nr && was_present)
					__atomic_fetch_add(&kcov_shm->cmp_shared_tier_shadow_dedup_supplied,
							   1UL,
							   __ATOMIC_RELAXED);
				if (now_excluded)
					__atomic_fetch_add(&kcov_shm->cmp_shared_tier_entry_path_excluded_ips,
							   1UL,
							   __ATOMIC_RELAXED);
			}
			return;
		}
		/* Collision on a different cmp_ip; continue linear probe. */
	}
	unlock(&cmp_hints_shm->shared_tier_lock);
	/* Probe exhausted; drop silently.  Fallback tier -- the per-nr
	 * pools still carry the authoritative record. */
}

/*
 * Measure-only would-confirm sibling of the eligible cold-miss bump
 * below.  Deterministically elects the first occupied, non-entry-
 * path-excluded shared-tier bucket by ascending index and checks
 * whether the elected (cmp_ip, value, size) triple is already
 * present in THIS nr's own native durable / recent pool at probe
 * time (exact identity match).  A hit bumps
 * cmp_shared_tier_shadow_would_confirm; a miss (or absent context)
 * bumps nothing.  READ-ONLY across every pool it touches: no lock,
 * no RNG, no generator-state advance, no counter mutation beyond
 * the one would-confirm scalar.  Called STRICTLY inside the same
 * eligible branch that bumps cmp_shared_tier_shadow_warmstart_
 * eligible so would_confirm <= warmstart_eligible holds and the
 * ratio reads as a per-mille rate.
 *
 * "THIS nr" is read off this_child()->syscall -- the syscall the
 * dispatch layer stamped before generate_syscall_args() fired; a
 * parent-context caller (init self-check path) short-circuits on
 * child == NULL and never bumps would_confirm.  Election ignores
 * the shared_tier_lock: occupied / value_count are RELAXED reads
 * and a torn observation at worst misbuckets a single sample,
 * matching the tier's advisory-shadow discipline.
 *
 * "Present now" is a CONSERVATIVE floor.  A native pool that will
 * eventually observe the triple but has not yet at probe time
 * reads as a miss, and the childop_consume path passes a wrapped
 * nr to cmp_hints_try_get_ex while this_child()->syscall.nr stays
 * the outer trinity_cmp_syscall's nr, so the scan hits the outer
 * syscall's pool instead of the wrapped nr's.  Both directions
 * push the count DOWN vs the true would-confirm rate, which is
 * the direction the go / no-go decision needs.
 */
static void cmp_shared_tier_shadow_probe_would_confirm(void)
{
	struct childdata *child;
	struct syscallrecord *rec;
	unsigned int nr;
	bool do32;
	unsigned long served_cmp_ip = 0;
	unsigned long served_value = 0;
	unsigned int served_size = 0;
	bool have_pick = false;
	uint32_t idx;
	struct cmp_hint_pool *native_pool;
	struct cmp_recent_pool *recent_pool;
	unsigned int native_count;
	unsigned int recent_count;
	unsigned int i;

	if (cmp_hints_shm == NULL)
		return;
	child = this_child();
	if (child == NULL)
		return;
	rec = &child->syscall;
	nr = rec->nr;
	if (nr >= MAX_NR_SYSCALL)
		return;
	do32 = rec->do32bit;

	/* Deterministic index-0-forward election.  RELAXED reads on
	 * occupied / entry_path_excluded / value_count mirror the sibling
	 * eligibility check's discipline; probe exhaustion (empty tier
	 * modulo entry-path noise) drops out silently with have_pick
	 * false. */
	for (idx = 0; idx < CMP_SHARED_TIER_IPS; idx++) {
		struct cmp_shared_tier_bucket *b =
			&cmp_hints_shm->shared_tier[idx];

		if (b->occupied == 0)
			continue;
		if (b->entry_path_excluded)
			continue;
		if (b->value_count == 0)
			continue;
		served_cmp_ip = b->cmp_ip;
		served_value = b->values[0].value;
		served_size = b->values[0].size;
		have_pick = true;
		break;
	}
	if (!have_pick)
		return;

	/* Scan THIS nr's own native durable pool for exact identity
	 * match.  ACQUIRE on count pairs with the RELEASE-store the
	 * durable insert path emits under the pool lock; any count
	 * above the per-syscall cap is a wild-write symptom and the
	 * pool is treated as empty for the probe (the sticky
	 * cmp_hints_pool_corrupted latch on the next real reader
	 * access still picks up the corruption via the normal path). */
	native_pool = &cmp_hints_shm->pools[nr][do32 ? 1 : 0];
	native_count = __atomic_load_n(&native_pool->count, __ATOMIC_ACQUIRE);
	if (native_count > CMP_HINTS_PER_SYSCALL)
		native_count = 0;
	for (i = 0; i < native_count; i++) {
		struct cmp_hint_entry *e = &native_pool->entries[i];

		if (e->cmp_ip == served_cmp_ip &&
		    e->value == served_value &&
		    e->size == served_size) {
			__atomic_fetch_add(&kcov_shm->cmp_shared_tier_shadow_would_confirm,
					   1UL, __ATOMIC_RELAXED);
			return;
		}
	}

	/* Then this nr's recent ring under the same skip-if-oob
	 * discipline.  Recent entries mirror the durable entry triple
	 * layout for the fields this probe reads (cmp_ip / value /
	 * size); a hit bumps and returns so a triple present in both
	 * tiers only counts once, keeping the invariant. */
	recent_pool = &cmp_hints_shm->recent_pools[nr][do32 ? 1 : 0];
	recent_count = __atomic_load_n(&recent_pool->count, __ATOMIC_ACQUIRE);
	if (recent_count > CMP_RECENT_PER_SYSCALL)
		recent_count = 0;
	for (i = 0; i < recent_count; i++) {
		struct cmp_recent_entry *e = &recent_pool->entries[i];

		if (e->cmp_ip == served_cmp_ip &&
		    e->value == served_value &&
		    e->size == served_size) {
			__atomic_fetch_add(&kcov_shm->cmp_shared_tier_shadow_would_confirm,
					   1UL, __ATOMIC_RELAXED);
			return;
		}
	}
}

void cmp_shared_tier_shadow_probe_cold_miss(void)
{
	unsigned long ips;
	unsigned long excluded;

	/* OFF-mode short-circuit BEFORE any shared-tier / counter access
	 * so a default build's get-path is bit-for-bit identical to a
	 * pre-tier baseline: no shm reads, no counter bump.  Same RELAXED
	 * discipline as cmp_shared_tier_insert()'s mode load. */
	if (__atomic_load_n(&cmp_shared_tier_mode, __ATOMIC_RELAXED) ==
	    CMP_SHARED_TIER_MODE_OFF)
		return;
	if (kcov_shm == NULL)
		return;

	/* Lock-free eligibility check.  The shared tier maintains three
	 * monotonically non-decreasing counters (cmp_shared_tier_ips /
	 * _entries / _entry_path_excluded_ips) under RELAXED atomics, so
	 * the running "non-entry-path IPs available" is exactly
	 * ips - excluded (both never decrease -- see the counter
	 * discipline in cmp_shared_tier_insert()).  Torn cross-counter
	 * reads at worst misbucket a single probe sample, which matches
	 * the tier's advisory-shadow discipline; the next miss resamples.
	 * ZERO shared_tier_lock traffic on the get-path probe. */
	ips = __atomic_load_n(&kcov_shm->cmp_shared_tier_ips,
			      __ATOMIC_RELAXED);
	excluded = __atomic_load_n(&kcov_shm->cmp_shared_tier_entry_path_excluded_ips,
				   __ATOMIC_RELAXED);
	if (ips > excluded) {
		__atomic_fetch_add(&kcov_shm->cmp_shared_tier_shadow_warmstart_eligible,
				   1UL, __ATOMIC_RELAXED);
		cmp_shared_tier_shadow_probe_would_confirm();
	}
}

/*
 * Per-eligible-cold-miss dice for the COMBINED-mode quarantined
 * shared-tier serve.  Fires the serve on 1 / CMP_SHARED_TIER_SERVE_
 * DICE of the opportunities cmp_shared_tier_shadow_probe_cold_miss()
 * has already bumped so the live serve rate stays a small fraction
 * of the shadow eligibility rate, preventing a run that turns
 * COMBINED on from flooding the cold-miss lane with cross-syscall
 * values before the wins/misses conversion metric has anything to
 * say about their quality.  Same discipline the sibling SHADOW-arm
 * dice gates use.
 */
#define CMP_SHARED_TIER_SERVE_DICE 4U

bool cmp_shared_tier_try_serve_cold_miss(unsigned int nr, bool do32,
					 enum cmp_hint_use use,
					 unsigned long old,
					 const struct cmp_accept_range *accept,
					 enum cmp_hint_callsite callsite,
					 unsigned long *out,
					 unsigned int *out_size)
{
	unsigned long ips;
	unsigned long excluded;
	unsigned long served_value = 0;
	unsigned long served_cmp_ip = 0;
	unsigned int served_size = 0;
	unsigned long transformed;
	bool have_pick = false;
	uint32_t start;
	unsigned int probe;

	/* Live serve gated on COMBINED mode only: OFF and SHADOW_ONLY
	 * keep the get-path bit-for-bit identical to a pre-serve
	 * baseline (the sibling shadow probe above still runs and
	 * accumulates the opportunity denominator).  RELAXED mode load
	 * matches the discipline every other cmp_shared_tier_mode read
	 * in this TU uses -- the mode is a startup-time knob, never
	 * flipped mid-run, so a racing load can never observe a partial
	 * store. */
	if (__atomic_load_n(&cmp_shared_tier_mode, __ATOMIC_RELAXED) !=
	    CMP_SHARED_TIER_MODE_COMBINED)
		return false;
	if (cmp_hints_shm == NULL)
		return false;

	/* Budget gate BEFORE the tier lock so a rate-limited miss pays
	 * no lock cost and does not walk the bucket grid. */
	if (!ONE_IN(CMP_SHARED_TIER_SERVE_DICE))
		return false;

	/* Non-entry-path availability check identical to the shadow
	 * probe's, so a run whose tier has only entry-path IPs (or is
	 * empty) short-circuits before acquiring the tier lock. */
	if (kcov_shm == NULL)
		return false;
	ips = __atomic_load_n(&kcov_shm->cmp_shared_tier_ips,
			      __ATOMIC_RELAXED);
	excluded = __atomic_load_n(&kcov_shm->cmp_shared_tier_entry_path_excluded_ips,
				   __ATOMIC_RELAXED);
	if (ips <= excluded)
		return false;

	/* Random-start linear probe for the first occupied, non-entry-
	 * path-excluded bucket with at least one value slot filled.
	 * Bounded at CMP_SHARED_TIER_PROBE_MAX per the tier's fallback
	 * discipline -- probe exhaustion drops silently, same shape as
	 * the insert path's collision drop.  The bucket picked is
	 * value-slot-random within the chosen bucket so a hot bucket
	 * with 8 values does not always serve slot 0. */
	start = rnd_modulo_u32(CMP_SHARED_TIER_IPS);
	lock(&cmp_hints_shm->shared_tier_lock);
	for (probe = 0; probe < CMP_SHARED_TIER_PROBE_MAX; probe++) {
		uint32_t idx = (start + probe) & (CMP_SHARED_TIER_IPS - 1U);
		struct cmp_shared_tier_bucket *b =
			&cmp_hints_shm->shared_tier[idx];
		unsigned int vcount;
		unsigned int slot;

		if (b->occupied == 0)
			continue;
		if (b->entry_path_excluded)
			continue;
		vcount = b->value_count;
		if (vcount == 0)
			continue;
		if (vcount > CMP_SHARED_TIER_VALUES)
			vcount = CMP_SHARED_TIER_VALUES;
		slot = rnd_modulo_u32(vcount);
		served_value = b->values[slot].value;
		served_size = b->values[slot].size;
		served_cmp_ip = b->cmp_ip;
		have_pick = true;
		break;
	}
	unlock(&cmp_hints_shm->shared_tier_lock);

	if (!have_pick)
		return false;

	/* Transform + caller accept-range gate BEFORE the serve is
	 * committed.  An accept-rejected value bumps a dedicated
	 * shared-tier reject counter -- the invalid-rate half of the
	 * measurement -- and does NOT bump cmp_shared_tier_serves, so
	 * the wins/misses conversion rate's denominator only counts
	 * values that actually reached the caller.  Mirrors the
	 * CMP_HYP_LIVE_INJECT_REASON_ACCEPT_REJECT bookkeeping the
	 * typed inject arm uses. */
	transformed = cmp_hint_apply_transform(served_value, use, old);
	if (accept != NULL &&
	    (transformed < accept->lo || transformed > accept->hi)) {
		__atomic_fetch_add(&kcov_shm->cmp_shared_tier_serve_accept_reject,
				   1UL, __ATOMIC_RELAXED);
		return false;
	}

	*out = transformed;
	if (out_size != NULL)
		*out_size = served_size;

	__atomic_fetch_add(&kcov_shm->cmp_shared_tier_serves, 1UL,
			   __ATOMIC_RELAXED);

	/* Stash under the CMP_HINT_POOL_KIND_NR sentinel so every
	 * pool-kind-gated bump in cmp_hints_stash_consumed() and the
	 * credit drain silently skips this entry.  The served_from_
	 * shared=1 stamp is what routes the PC outcome to
	 * cmp_hint_tier_shared_wins / _misses in the drain; every
	 * other native credit lane (per-entry pool wins, by-pool /
	 * by-callsite / by-tier / by-age partitions, typed-hyp
	 * consume/would-pick) is gated OFF for this entry.  arg_idx /
	 * field_idx / desc are unused (per-syscall-shape stash) and
	 * age_bucket is zero because the shared tier has no per-entry
	 * LRU stamp -- same shape the recent-tier stash uses.  The
	 * cmp_ip carried on the stash is the tier bucket's cmp_ip
	 * (may belong to another syscall's observation); it is used
	 * as a stable identifier for the shared-tier lane, never
	 * looked up against this nr's native pool. */
	cmp_hints_stash_consumed(nr, do32, CMP_HINT_POOL_KIND_NR,
				 callsite,
				 served_cmp_ip, served_value, served_size,
				 use, 0, 0, NULL,
				 false, 0, false, true);
	return true;
}

void cmp_shared_tier_populate_from_pools(void)
{
	unsigned int nr, a, k;

	/* OFF-mode short-circuit BEFORE the pools[][] walk so a default
	 * warm-load skips the 2 * MAX_NR_SYSCALL * CMP_HINTS_PER_SYSCALL
	 * per-entry loop entirely -- no cmp_shared_tier_insert() calls,
	 * no shm reads.  Redundant with the per-insert short-circuit
	 * (which already bails without touching the tier) but eliminates
	 * even the loop's per-entry corruption gate cost so a pre-tier
	 * baseline and an OFF build share the same boot-time profile. */
	if (__atomic_load_n(&cmp_shared_tier_mode, __ATOMIC_RELAXED) ==
	    CMP_SHARED_TIER_MODE_OFF)
		return;
	if (cmp_hints_shm == NULL)
		return;

	for (nr = 0; nr < MAX_NR_SYSCALL; nr++) {
		for (a = 0; a < 2; a++) {
			struct cmp_hint_pool *pool =
				&cmp_hints_shm->pools[nr][a];
			unsigned int count;

			count = __atomic_load_n(&pool->count,
						__ATOMIC_ACQUIRE);
			/* Skip stomped or empty pools (safe_count returns 0
			 * on either).  cmp_hints_load_file() runs in parent
			 * context at boot before any child has started, so a
			 * concurrent stomp is not a realistic threat -- the
			 * gate is belt-and-braces against a future caller. */
			if (count == 0 ||
			    cmp_hints_pool_corrupted(pool, count))
				continue;
			if (count > CMP_HINTS_PER_SYSCALL)
				count = CMP_HINTS_PER_SYSCALL;
			for (k = 0; k < count; k++) {
				cmp_shared_tier_insert(nr,
					pool->entries[k].cmp_ip,
					pool->entries[k].value,
					pool->entries[k].size);
			}
		}
	}
}

