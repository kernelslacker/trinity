/*
 * alloc_track: the opt-in side-set of live zmalloc_tracked() results that
 * gates every free().  df_alloc_track[] is the source of truth, a hash mirrors
 * it for membership and a parallel array records each extent;
 * df_tracked_free_checked() frees only what df_alloc_track_consume() proves
 * live.
 */

#include <stdint.h>
#include <stdlib.h>

#include "child.h"
#include "deferred-free.h"
#include "shm.h"
#include "stats_ring.h"

#include "deferred-free-internal.h"

/*
 * Opt-in side-set of live malloc results.  Sites whose pointer flows
 * through deferred_free_enqueue() allocate via zmalloc_tracked();
 * enqueue consumes the matching entry to confirm a real malloc start
 * before free().  Opt-in (not every zmalloc) so direct-free sites
 * don't leave stale entries a fuzzed scribble could match; a missed
 * opt-in degrades to a reject leak (observable in stats), the safe
 * direction to err.
 *
 * Sized (4096) for the in-flight window -- a sanitise's zmalloc to its
 * post handler's enqueue spans well under 100 zmallocs; overflow
 * evicts in arrival order (benign leak of the evicted free).
 * Process-local: zero-init BSS, COW at fork, single-threaded by the
 * owning child, no locking.
 */

void **df_alloc_track;
static unsigned int alloc_track_head;

/*
 * Parallel size storage indexed identically to df_alloc_track[]: each
 * slot records the allocation extent passed to deferred_alloc_track()
 * at registration time, so a consumer that holds a tracked pointer
 * (the nested-address scrub and setsockopt today) can recover the
 * real allocation length without re-asking the allocator.  Shares the
 * alloc_track_base mmap'd region so the same mprotect bracket covers
 * it -- a fuzzed value-result syscall that aliases these pages hits
 * the PROT_READ wall instead of silently flipping a recorded size.
 * Slot index matches df_alloc_track[]: a consume() that nulls
 * df_alloc_track[idx] MUST zero df_alloc_track_sizes[idx] in the same
 * bracket so the size cannot survive its pointer (a stale non-zero
 * size lingering after the slot rotated out would feed a downstream
 * bound check with a length that does not belong to the value the
 * caller actually holds).
 */
size_t *df_alloc_track_sizes;

void **df_alloc_track_hash;

static inline unsigned int alloc_track_hash_index(void *ptr)
{
	uint64_t key = (uint64_t)(uintptr_t)ptr >> 4;

	return (unsigned int)((key * ALLOC_TRACK_FIB_MUL) >>
			      (64 - ALLOC_TRACK_HASH_SHIFT));
}

/*
 * Idempotent insert: a second insert of an already-present ptr is a
 * no-op.  Matches the "ptr appears in array iff present in hash"
 * mirror semantics when a df_alloc_track[] write happens to land the
 * same pointer in the same slot it already occupied.  Bounded loop:
 * occupancy is capped at ALLOC_TRACK_SIZE (4096) << table size, so a
 * full table is impossible from the mirror path; the bound is a
 * paranoia rail to keep a corruption-induced runaway from hanging.
 */
static void alloc_track_hash_insert(void *ptr)
{
	unsigned int idx = alloc_track_hash_index(ptr);
	unsigned int probes;

	for (probes = 0; probes < ALLOC_TRACK_HASH_SIZE; probes++) {
		if (df_alloc_track_hash[idx] == NULL) {
			df_alloc_track_hash[idx] = ptr;
			return;
		}
		if (df_alloc_track_hash[idx] == ptr)
			return;
		idx = (idx + 1) & ALLOC_TRACK_HASH_MASK;
	}
}

/*
 * Shift-back deletion: walk forward from the hole, pulling any entry
 * whose probe chain would have stopped at the hole back into it, until
 * we hit a NULL slot.  Preserves the open-addressing invariant that
 * lookup terminates at the first NULL after the entry's natural slot.
 *
 * The move test compares "distance from natural to current slot" vs
 * "distance from hole to current slot".  If the entry's natural slot
 * is at or before the hole (in chain order, modulo wrap), moving it
 * back keeps it reachable from natural.
 */
static void alloc_track_hash_remove(void *ptr)
{
	unsigned int idx = alloc_track_hash_index(ptr);
	unsigned int hole;
	unsigned int probes;

	for (probes = 0; probes < ALLOC_TRACK_HASH_SIZE; probes++) {
		if (df_alloc_track_hash[idx] == NULL)
			return;
		if (df_alloc_track_hash[idx] == ptr)
			break;
		idx = (idx + 1) & ALLOC_TRACK_HASH_MASK;
	}
	if (df_alloc_track_hash[idx] != ptr)
		return;

	hole = idx;
	for (probes = 0; probes < ALLOC_TRACK_HASH_SIZE; probes++) {
		unsigned int natural;
		unsigned int dist_to_hole;
		unsigned int dist_to_natural;

		idx = (idx + 1) & ALLOC_TRACK_HASH_MASK;
		if (df_alloc_track_hash[idx] == NULL) {
			df_alloc_track_hash[hole] = NULL;
			return;
		}
		natural = alloc_track_hash_index(df_alloc_track_hash[idx]);
		dist_to_hole = (idx - hole) & ALLOC_TRACK_HASH_MASK;
		dist_to_natural = (idx - natural) & ALLOC_TRACK_HASH_MASK;
		if (dist_to_natural >= dist_to_hole) {
			df_alloc_track_hash[hole] = df_alloc_track_hash[idx];
			hole = idx;
		}
	}
	/* Unreachable in a well-formed table; if we got here, the table
	 * is corrupt or fully-occupied with no NULLs.  Clear the hole
	 * we know about and bail. */
	df_alloc_track_hash[hole] = NULL;
}

/*
 * Membership probe against the alloc_track side-set.  The hash mirrors
 * df_alloc_track[] for the O(1) hit case, but a hash miss is NOT proof of
 * absence: deferred_alloc_track()'s duplicate-ptr insert is idempotent
 * on the hash (same value already present -> no-op) yet still writes a
 * fresh df_alloc_track[] slot, so a subsequent displaced-eviction of the
 * older slot removes the hash entry while the newer df_alloc_track[] slot
 * still holds @ptr.  Falling back to a linear df_alloc_track[] scan on a
 * NULL-slot hash miss restores the "array is source of truth" invariant
 * the fail-closed callers below assume (all of them leak-on-miss
 * rather than free-on-miss, so a false negative just leaks the chunk
 * until child exit -- but that leak still shows up as bad user-visible
 * behaviour: rejected enqueues at :1446, bpf_free_filter inner-buffer
 * skips at net/bpf/bpf.c:516, cleanup_release_post_state drops at :939).
 * The hash-repair path is intentionally NOT walked here -- the lookup
 * hot path executes against the PROT_READ steady state, and an
 * mprotect RW bracket to reinsert the missing entry would eat the
 * PROT_READ speedup for the (rare) desync case.  A fallback hit bumps
 * alloc_track_lookup_array_fallback_hit so operators can see when the
 * desync is firing.
 */
bool alloc_track_lookup(void *ptr)
{
	unsigned int idx = alloc_track_hash_index(ptr);
	unsigned int probes;

	for (probes = 0; probes < ALLOC_TRACK_HASH_SIZE; probes++) {
		if (df_alloc_track_hash[idx] == NULL)
			goto fallback;
		if (df_alloc_track_hash[idx] == ptr)
			return true;
		idx = (idx + 1) & ALLOC_TRACK_HASH_MASK;
	}
fallback:
	for (probes = 0; probes < ALLOC_TRACK_SIZE; probes++) {
		if (df_alloc_track[probes] == ptr) {
			__atomic_add_fetch(&shm->stats.deferred_free.alloc_track_lookup_array_fallback_hit,
					   1, __ATOMIC_RELAXED);
			return true;
		}
	}
	return false;
}

/*
 * Gated by alloc_track_lookup(): a hash hit accepts in O(1), a hash
 * miss falls back to a linear df_alloc_track[] scan (so a mirror-desync
 * @ptr still gates in), and only a miss there rejects -- the reject is
 * the slow path.  Hits proceed to the backward scan below to locate
 * the slot whose ptr matches, then read the parallel sizes array.
 * Backward-from-head walks the recently-inserted entries first;
 * most callers look up a buffer registered a handful of allocations
 * earlier (sanitiser zmalloc_tracked just before dispatch), so the
 * scan terminates close to head.  Reads run against the
 * PROT_READ steady state -- no mprotect bracket on this hot path.
 * Returns 0 on miss so the caller can treat "unknown extent" as "do
 * not derive a bound" (the safer direction: a downstream read gated on
 * lookup_size > 0 skips when we cannot prove the buffer's length).
 */
size_t alloc_track_lookup_size(void *ptr)
{
	unsigned int idx;
	unsigned int i;

	if (ptr == NULL || !alloc_track_lookup(ptr))
		return 0;

	idx = (alloc_track_head - 1) & (ALLOC_TRACK_SIZE - 1);
	for (i = 0; i < ALLOC_TRACK_SIZE; i++) {
		if (df_alloc_track[idx] == ptr)
			return df_alloc_track_sizes[idx];
		idx = (idx - 1) & (ALLOC_TRACK_SIZE - 1);
	}
	return 0;
}

void deferred_alloc_track(void *ptr, size_t size)
{
	unsigned int slot;
	void *displaced;

	if (ptr == NULL)
		return;

	if (df_alloc_track_unlock() != 0)
		return;

	slot = alloc_track_head & (ALLOC_TRACK_SIZE - 1);
	displaced = df_alloc_track[slot];

	df_alloc_track[slot] = ptr;
	df_alloc_track_sizes[slot] = size;
	alloc_track_head++;

	alloc_track_hash_insert(ptr);
	/*
	 * displaced == ptr means the slot already held this same pointer
	 * (duplicate-ptr edge case described above the hash table): the
	 * array's net state is unchanged, so the paired hash_remove would
	 * incorrectly drop the entry we just confirmed.  Skip it.
	 */
	if (displaced != NULL && displaced != ptr)
		alloc_track_hash_remove(displaced);

	df_alloc_track_lock();
}

/*
 * Consume the entry matching @ptr.  Returns true if found (and clears
 * the slot); false if the pointer was not in the side-set, meaning the
 * caller is about to free something __zmalloc() never produced.
 *
 * Backward scan from head against df_alloc_track[] (source of truth) --
 * NO hash-lookup fast-reject.  A miss on the hash is not proof of
 * absence: an aggressive glibc address reuse can land the same pointer
 * in two different df_alloc_track[] slots (deferred_alloc_track does not
 * scrub the older slot when its insert idempotently no-ops on the
 * duplicate), and a later displaced-eviction of the older slot then
 * removes the hash entry while the newer slot still holds the pointer.
 * Treating a hash miss as "untracked" in that state would leak the
 * newer slot instead of freeing it, so the array is the definitive
 * check.  In practice the scan stays cheap because post handlers free
 * a few syscalls after the matching __zmalloc -- the hit lives near
 * head (PATHNAME / IOVEC / SOCKADDR generators enqueue 1-3 pointers
 * per arg).
 */
bool df_alloc_track_consume(void *ptr)
{
	unsigned int idx;
	unsigned int i;

	if (ptr == NULL)
		return false;

	idx = (alloc_track_head - 1) & (ALLOC_TRACK_SIZE - 1);
	for (i = 0; i < ALLOC_TRACK_SIZE; i++) {
		if (df_alloc_track[idx] == ptr) {
			if (df_alloc_track_unlock() != 0)
				return false;
			df_alloc_track[idx] = NULL;
			df_alloc_track_sizes[idx] = 0;
			alloc_track_hash_remove(ptr);
			df_alloc_track_lock();
			return true;
		}
		idx = (idx - 1) & (ALLOC_TRACK_SIZE - 1);
	}
	return false;
}

/*
 * Free-time ownership gate: only a true return from df_alloc_track_consume()
 * is proof that __zmalloc() currently owns @ptr; a miss swallows the free
 * and bumps a per-site counter for telemetry.  Do NOT gate on
 * alloc_track_lookup() -- it is a value-keyed prefilter that desyncs from
 * the array (rotation / duplicate-ptr edge case).  See
 * Documentation/deferred-free.md "Ownership gate: df_alloc_track_consume vs
 * alloc_track_lookup" for the historical bad-free class this replaced.
 * Returns true iff @ptr was freed.
 */
bool df_tracked_free_checked(void *ptr, enum tracked_free_site site)
{
	struct childdata *c;

	if (df_alloc_track_consume(ptr)) {
		free(ptr);
		return true;
	}

	switch (site) {
	case TRACKED_FREE_SITE_RING_EVICT:
		c = this_child();
		if (c != NULL && c->stats_ring != NULL)
			stats_ring_enqueue(c->stats_ring,
					   STATS_FIELD_RING_EVICTION_CORRUPT,
					   0, 1);
		else
			parent_stats.ring_eviction_corrupt++;
		break;
	case TRACKED_FREE_SITE_RING_DRAIN:
	case TRACKED_FREE_SITE_GEN_RETIRE:
		/* Both drains route consume-miss attribution through the
		 * same corrupt-ptr counter: the arena retire is
		 * definitionally the "later" tail of the ring drain, and
		 * a consume miss at either site says the same thing --
		 * the recorded alloc_track slot no longer matches this
		 * value, so free()ing it would risk a bad-free.
		 */
		c = this_child();
		if (c != NULL && c->stats_ring != NULL)
			stats_ring_enqueue(c->stats_ring,
					   STATS_FIELD_DEFERRED_FREE_CORRUPT_PTR,
					   0, 1);
		else
			parent_stats.deferred_free_corrupt_ptr++;
		break;
	case TRACKED_FREE_SITE_IMMEDIATE:
		__atomic_add_fetch(&shm->stats.deferred_free.reject_untracked,
				   1, __ATOMIC_RELAXED);
		break;
	}
	return false;
}
