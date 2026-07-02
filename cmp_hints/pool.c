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
		__atomic_fetch_add(&kcov_shm->cmp_hints_count_oob, 1UL,
				   __ATOMIC_RELAXED);
		if (pool->canary_lock_post != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->cmp_hints_canary_lock_post_corrupt,
					   1UL, __ATOMIC_RELAXED);
		if (pool->canary_pre != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->cmp_hints_canary_pre_corrupt,
					   1UL, __ATOMIC_RELAXED);
		if (pool->canary_post != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->cmp_hints_canary_post_corrupt,
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
				__atomic_fetch_add(&kcov_shm->cmp_hints_save_reject_dup,
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
			__atomic_fetch_add(&kcov_shm->cmp_hints_unique_inserts,
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
		__atomic_fetch_add(&kcov_shm->cmp_hints_unique_inserts, 1UL,
				   __ATOMIC_RELAXED);
		/* Evict-replace pressure: a tuple displaced an older one
		 * because the per-syscall cap was full.  The new entry won
		 * the slot (counted via cmp_hints_unique_inserts above) and
		 * the evicted entry is the silent loser; the cap counter
		 * tracks displacement events so a saturated pool is
		 * directly visible as cap > unique_inserts_delta over a
		 * window once the per-syscall pool tops out. */
		__atomic_fetch_add(&kcov_shm->cmp_hints_save_reject_cap, 1UL,
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
			__atomic_fetch_add(&kcov_shm->per_syscall_cmp_reject_cap[nr],
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
		__atomic_fetch_add(&kcov_shm->cmp_recent_inserts, 1UL,
				   __ATOMIC_RELAXED);
		if (count >= CMP_RECENT_PER_SYSCALL)
			__atomic_fetch_add(&kcov_shm->cmp_recent_evicts, 1UL,
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
		}
	}
	pool_unlock(pool);
	return inserted;
}

