/*
 * Deferred-free queue: hold syscall-owned allocations for 5-50 more
 * syscalls instead of freeing them at return, so multiple allocations
 * overlap in time and expose kernel UAF / stale-ref / double-free.
 * Membership tests go through a side hash, not a linear ring walk, so
 * per-tick cost stays flat under millions of syscalls.
 */

#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "child.h"
#include "deferred-free.h"
#include "pc_format.h"
#include "random.h"
#include "shm.h"
#include "stats_ring.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
#define DEFERRED_RING_SIZE	64
#define DEFERRED_TTL_MIN	5
#define DEFERRED_TTL_MAX	50

/*
 * Argtype tag set by generic_free_arg around each ops->cleanup() call so
 * deferred_free_reject_bump can attribute rejects to the cleanup hook
 * that drove them.  Direct (non-cleanup-loop) callers leave this at
 * ARG_UNDEFINED, which feeds the OTHER shard.
 */
static enum argtype current_cleanup_argtype = ARG_UNDEFINED;

void deferred_free_set_cleanup_argtype(enum argtype t)
{
	current_cleanup_argtype = t;
}

enum argtype deferred_free_get_cleanup_argtype(void)
{
	return current_cleanup_argtype;
}

/*
 * Decrement-and-free runs 1-in-N ticks (N power-of-two -> bitmask);
 * the other N-1 bail before the mprotect bracket.  Effective TTL is
 * thus ~N x the 5-50 nominal (80-800 syscalls) -- intentional
 * headroom for UAF overlap.
 */
#define DEFERRED_TICK_BATCH	16

struct deferred_entry {
	void *ptr;
	unsigned int ttl;
};

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
/* 4096 slots.  Long-lived MMAP_ANON pool entries must stay tracked
 * until their child cycle completes, or get_map_handle's
 * alloc_track_lookup gate false-rejects legitimate slots and burns
 * retry budget.  4096 holds those pool entries plus recent
 * zmalloc_tracked churn without rotating live entries out from under
 * the lookup. */
#define ALLOC_TRACK_SIZE	4096

/*
 * alloc_track[] and alloc_track_hash[] share a single mmap'd backing
 * region so one mprotect bracket covers both arrays' pages, halving
 * the syscall cost on the deferred_alloc_track hot path (which writes
 * both in one operation).  The base, size, and array pointers below
 * are set up in deferred_free_init().  Steady state is PROT_READ so
 * the lookup hot path (alloc_track_lookup, called from every
 * cleanup_release_post_state and the deferred-free enqueue gate)
 * reads directly without an mprotect syscall; only the writer entry
 * points (deferred_alloc_track, alloc_track_consume) flip RW for the
 * duration of the mutation.
 */
static void **alloc_track;
static unsigned int alloc_track_head;
static void *alloc_track_base;
static size_t alloc_track_bytes;

/*
 * Parallel size storage indexed identically to alloc_track[]: each
 * slot records the allocation extent passed to deferred_alloc_track()
 * at registration time, so a consumer that holds a tracked pointer
 * (cmp_hints field scan today) can recover the real allocation length
 * without re-asking the allocator.  Shares the alloc_track_base
 * mmap'd region so the same mprotect bracket covers it -- a fuzzed
 * value-result syscall that aliases these pages hits the PROT_READ
 * wall instead of silently flipping a recorded size.  Slot index
 * matches alloc_track[]: a consume() that nulls alloc_track[idx]
 * MUST zero alloc_track_sizes[idx] in the same bracket so the size
 * cannot survive its pointer (a stale non-zero size lingering after
 * the slot rotated out would feed a downstream bound check with a
 * length that does not belong to the value the caller actually
 * holds).
 */
static size_t *alloc_track_sizes;

/*
 * Membership accelerator for alloc_track[]: 16384-slot open-addressed
 * hash mirroring the array so both hit and miss are O(1).  alloc_track[]
 * stays source of truth; the hash mirrors it for membership only.
 * Steady state PROT_READ is load-bearing for memory safety (slots feed
 * free() gates), not just a perf nicety.  See Documentation/deferred-free.md
 * "alloc_track hash table" for the full rationale (sizing, Fibonacci
 * hashing, duplicate-ptr edge case).
 */
#define ALLOC_TRACK_HASH_SHIFT	14
#define ALLOC_TRACK_HASH_SIZE	(1U << ALLOC_TRACK_HASH_SHIFT)
#define ALLOC_TRACK_HASH_MASK	(ALLOC_TRACK_HASH_SIZE - 1U)

/* 2^64 / phi, rounded to nearest odd: the 64-bit Fibonacci constant. */
#define ALLOC_TRACK_FIB_MUL	0x9E3779B97F4A7C15ULL

static void **alloc_track_hash;

static inline unsigned int alloc_track_hash_index(void *ptr)
{
	uint64_t key = (uint64_t)(uintptr_t)ptr >> 4;

	return (unsigned int)((key * ALLOC_TRACK_FIB_MUL) >>
			      (64 - ALLOC_TRACK_HASH_SHIFT));
}

/*
 * Flip the alloc_track / alloc_track_hash backing to PROT_READ|WRITE
 * for a single mutation, then back to PROT_READ.  Lookups read
 * directly against the PROT_READ steady state -- no bracket on the
 * hot path.  An unlock failure leaves the page PROT_READ and the
 * caller skips its write; the side-set ends up with a missing entry
 * (subsequent deferred_free_enqueue of that ptr rejects it as
 * untracked and the ptr is leaked) or a stale entry (subsequent
 * alloc_track_lookup answers false-positive, the lookup result
 * still flows through the deferred-free shape/heap/shared-region
 * gates), both safer than silently flipping a membership bit.
 */
static int alloc_track_unlock(void)
{
	if (mprotect(alloc_track_base, alloc_track_bytes,
		     PROT_READ | PROT_WRITE) != 0) {
		outputerr("deferred_free: alloc_track unlock failed: "
			  "errno=%d\n", errno);
		return -1;
	}
	return 0;
}

static void alloc_track_lock(void)
{
	if (mprotect(alloc_track_base, alloc_track_bytes, PROT_READ) != 0)
		outputerr("deferred_free: alloc_track lock failed: "
			  "errno=%d\n", errno);
}

/*
 * Idempotent insert: a second insert of an already-present ptr is a
 * no-op.  Matches the "ptr appears in array iff present in hash"
 * mirror semantics when an alloc_track[] write happens to land the
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
		if (alloc_track_hash[idx] == NULL) {
			alloc_track_hash[idx] = ptr;
			return;
		}
		if (alloc_track_hash[idx] == ptr)
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
		if (alloc_track_hash[idx] == NULL)
			return;
		if (alloc_track_hash[idx] == ptr)
			break;
		idx = (idx + 1) & ALLOC_TRACK_HASH_MASK;
	}
	if (alloc_track_hash[idx] != ptr)
		return;

	hole = idx;
	for (probes = 0; probes < ALLOC_TRACK_HASH_SIZE; probes++) {
		unsigned int natural;
		unsigned int dist_to_hole;
		unsigned int dist_to_natural;

		idx = (idx + 1) & ALLOC_TRACK_HASH_MASK;
		if (alloc_track_hash[idx] == NULL) {
			alloc_track_hash[hole] = NULL;
			return;
		}
		natural = alloc_track_hash_index(alloc_track_hash[idx]);
		dist_to_hole = (idx - hole) & ALLOC_TRACK_HASH_MASK;
		dist_to_natural = (idx - natural) & ALLOC_TRACK_HASH_MASK;
		if (dist_to_natural >= dist_to_hole) {
			alloc_track_hash[hole] = alloc_track_hash[idx];
			hole = idx;
		}
	}
	/* Unreachable in a well-formed table; if we got here, the table
	 * is corrupt or fully-occupied with no NULLs.  Clear the hole
	 * we know about and bail. */
	alloc_track_hash[hole] = NULL;
}

bool alloc_track_lookup(void *ptr)
{
	unsigned int idx = alloc_track_hash_index(ptr);
	unsigned int probes;

	for (probes = 0; probes < ALLOC_TRACK_HASH_SIZE; probes++) {
		if (alloc_track_hash[idx] == NULL)
			return false;
		if (alloc_track_hash[idx] == ptr)
			return true;
		idx = (idx + 1) & ALLOC_TRACK_HASH_MASK;
	}
	return false;
}

/*
 * Hash-gated fast reject mirrors alloc_track_consume(): a miss
 * short-circuits without touching alloc_track[] / alloc_track_sizes[].
 * Hits proceed to the backward scan to locate the slot whose ptr
 * matches, then read the parallel sizes array.  Backward-from-head
 * walks the recently-inserted entries first; most cmp_hints field
 * scans look up a buffer registered a handful of allocations earlier
 * (sanitiser zmalloc_tracked just before dispatch), so the scan
 * terminates close to head.  Reads run against the PROT_READ steady
 * state -- no mprotect bracket on this hot path.  Returns 0 on miss
 * so the caller can treat "unknown extent" as "do not derive a bound"
 * (the safer direction: a downstream read gated on lookup_size > 0
 * skips when we cannot prove the buffer's length).
 */
size_t alloc_track_lookup_size(void *ptr)
{
	unsigned int idx;
	unsigned int i;

	if (ptr == NULL || !alloc_track_lookup(ptr))
		return 0;

	idx = (alloc_track_head - 1) & (ALLOC_TRACK_SIZE - 1);
	for (i = 0; i < ALLOC_TRACK_SIZE; i++) {
		if (alloc_track[idx] == ptr)
			return alloc_track_sizes[idx];
		idx = (idx - 1) & (ALLOC_TRACK_SIZE - 1);
	}
	return 0;
}

/*
 * In-flight pointer set: mirrors ring residency for GC reconciliation
 * of stomp orphans.  1024-slot open-addressed hash sharing the
 * alloc_track_hash storage shape; steady state PROT_READ, writers
 * bracket with inflight_unlock/lock.  NOT the free-time ownership gate
 * -- that role belongs to alloc_track_lookup (this one desynced under
 * stomp + unlock-window pressure).  See Documentation/deferred-free.md
 * "In-flight pointer set" for the full history and desync analysis.
 */
#define INFLIGHT_HASH_SHIFT	10
#define INFLIGHT_HASH_SIZE	(1U << INFLIGHT_HASH_SHIFT)
#define INFLIGHT_HASH_MASK	(INFLIGHT_HASH_SIZE - 1U)

static void **inflight_hash;
static size_t inflight_hash_bytes;

static inline unsigned int inflight_hash_index(void *ptr)
{
	uint64_t key = (uint64_t)(uintptr_t)ptr >> 4;

	return (unsigned int)((key * ALLOC_TRACK_FIB_MUL) >>
			      (64 - INFLIGHT_HASH_SHIFT));
}

/*
 * Flip the inflight_hash backing to PROT_READ|PROT_WRITE for the
 * duration of a single mutation, then back to PROT_READ.  Reads do not
 * need the bracket -- they execute directly against the PROT_READ
 * steady state.  A failed unlock leaves the page PROT_READ and the
 * caller skips its write; the leaked-positive (insert miss) or
 * stale-positive (remove miss) is bounded by the gc-sweep cadence and
 * is the safer direction to err vs. silently scribbling a wrong
 * membership bit.
 */
static int inflight_unlock(void)
{
	if (mprotect(inflight_hash, inflight_hash_bytes,
		     PROT_READ | PROT_WRITE) != 0) {
		outputerr("deferred_free: inflight_hash unlock failed: "
			  "errno=%d\n", errno);
		return -1;
	}
	return 0;
}

static void inflight_lock(void)
{
	if (mprotect(inflight_hash, inflight_hash_bytes, PROT_READ) != 0)
		outputerr("deferred_free: inflight_hash lock failed: "
			  "errno=%d\n", errno);
}

static void inflight_hash_insert(void *ptr)
{
	unsigned int idx = inflight_hash_index(ptr);
	unsigned int probes;

	if (inflight_unlock() != 0)
		return;

	for (probes = 0; probes < INFLIGHT_HASH_SIZE; probes++) {
		if (inflight_hash[idx] == NULL) {
			inflight_hash[idx] = ptr;
			break;
		}
		if (inflight_hash[idx] == ptr)
			break;
		idx = (idx + 1) & INFLIGHT_HASH_MASK;
	}

	inflight_lock();
}

static void inflight_hash_remove(void *ptr)
{
	unsigned int idx = inflight_hash_index(ptr);
	unsigned int hole;
	unsigned int probes;

	for (probes = 0; probes < INFLIGHT_HASH_SIZE; probes++) {
		if (inflight_hash[idx] == NULL)
			return;
		if (inflight_hash[idx] == ptr)
			break;
		idx = (idx + 1) & INFLIGHT_HASH_MASK;
	}
	if (inflight_hash[idx] != ptr)
		return;

	if (inflight_unlock() != 0)
		return;

	hole = idx;
	for (probes = 0; probes < INFLIGHT_HASH_SIZE; probes++) {
		unsigned int natural;
		unsigned int dist_to_hole;
		unsigned int dist_to_natural;

		idx = (idx + 1) & INFLIGHT_HASH_MASK;
		if (inflight_hash[idx] == NULL) {
			inflight_hash[hole] = NULL;
			inflight_lock();
			return;
		}
		natural = inflight_hash_index(inflight_hash[idx]);
		dist_to_hole = (idx - hole) & INFLIGHT_HASH_MASK;
		dist_to_natural = (idx - natural) & INFLIGHT_HASH_MASK;
		if (dist_to_natural >= dist_to_hole) {
			inflight_hash[hole] = inflight_hash[idx];
			hole = idx;
		}
	}
	inflight_hash[hole] = NULL;
	inflight_lock();
}

void deferred_alloc_track(void *ptr, size_t size)
{
	unsigned int slot;
	void *displaced;

	if (ptr == NULL)
		return;

	if (alloc_track_unlock() != 0)
		return;

	slot = alloc_track_head % ALLOC_TRACK_SIZE;
	displaced = alloc_track[slot];

	alloc_track[slot] = ptr;
	alloc_track_sizes[slot] = size;
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

	alloc_track_lock();
}

/*
 * Consume the entry matching @ptr.  Returns true if found (and clears
 * the slot); false if the pointer was not in the side-set, meaning the
 * caller is about to free something __zmalloc() never produced.
 *
 * Hash-gated fast reject: misses short-circuit without touching the
 * alloc_track[] array at all.  This is the path that fires when a
 * fuzzed scribble arrives at deferred_free_enqueue (heap-shape, not
 * malloc-returned), so the reject is O(1).
 *
 * Hits proceed to the backward scan to locate the slot for the mirror
 * clear.  The scan stays cheap in practice because post handlers free
 * a few syscalls after the matching __zmalloc -- the hit lives near
 * head (PATHNAME / IOVEC / SOCKADDR generators enqueue 1-3 pointers
 * per arg).  The fall-through return false at the end covers the
 * duplicate-ptr edge case where the hash records membership but the
 * specific slot has rotated out.
 */
static bool alloc_track_consume(void *ptr)
{
	unsigned int idx;
	unsigned int i;

	if (!alloc_track_lookup(ptr))
		return false;

	idx = (alloc_track_head - 1) & (ALLOC_TRACK_SIZE - 1);
	for (i = 0; i < ALLOC_TRACK_SIZE; i++) {
		if (alloc_track[idx] == ptr) {
			if (alloc_track_unlock() != 0)
				return false;
			alloc_track[idx] = NULL;
			alloc_track_sizes[idx] = 0;
			alloc_track_hash_remove(ptr);
			alloc_track_lock();
			return true;
		}
		idx = (idx - 1) & (ALLOC_TRACK_SIZE - 1);
	}
	return false;
}

/*
 * Ring storage lives in an mmap'd region whose address range is registered
 * with shared_regions[] via track_shared_region().  That tracking lets
 * avoid_shared_buffer() and the mm-syscall sanitisers refuse fuzzed
 * pointers/lengths that would land inside the ring.  Without that
 * registration a fuzzed write could scribble ring[i].ptr with a
 * pid-shaped value and the next deferred_free_tick() would free() the
 * bogus pointer.
 *
 * MAP_PRIVATE (not MAP_SHARED via alloc_shared()) is deliberate: the queue
 * is process-local by contract -- pointers come from each child's own
 * post-fork heap.  Sharing the ring across forks would let one child's
 * deferred_free_tick() free a pointer enqueued by a different child --
 * either a double free if both children reach ttl==0 on the same slot, or
 * cross-heap chunk-metadata corruption because the freeing child's glibc
 * has no record of an allocation at that address.  Each forked child needs
 * its own COW copy of the ring; only the address range is shared with
 * the tracker.
 */
/*
 * Ring control state -- the ring pointer, its mmap'd size, and the
 * in-flight slot count.  All three live in their own small mmap'd
 * armor page so a sibling fuzzed value-result syscall cannot scribble
 * the values that DRIVE ring[]'s own mprotect/munmap bracket: a
 * stomped ring would point mprotect at an arbitrary VA, a stomped
 * ring_bytes would extend munmap into unrelated VMAs, and a stomped
 * ring_count would mis-gate the enqueue full-ring check and the
 * tick early-bail.  ring and ring_bytes are write-once during init
 * (plus the dispose-time NULL/zero clear); ring_count mutates per
 * enqueue and drain.  Steady state of the armor page is PROT_READ so
 * the dominant reads (the "if (ring == NULL)" / "if (ring_count == 0)"
 * fast-bail checks, the ring_count comparison in the full-ring
 * branch) execute without a syscall; the few writer paths flip RW
 * via rc_unlock()/rc_lock() for the duration of the mutation.  The
 * field access pattern is hidden behind the file-scope macros below
 * so the rest of the file keeps reading like ring/ring_count/
 * ring_bytes were still plain file-static scalars.
 */
struct ring_control {
	struct deferred_entry *ring;
	size_t ring_bytes;
	unsigned int ring_count;
};

static struct ring_control *rc;
static size_t rc_bytes;

#define ring		(rc->ring)
#define ring_bytes	(rc->ring_bytes)
#define ring_count	(rc->ring_count)

static int rc_unlock(void)
{
	if (mprotect(rc, rc_bytes, PROT_READ | PROT_WRITE) != 0) {
		outputerr("deferred_free: ring_control unlock failed: "
			  "errno=%d\n", errno);
		return -1;
	}
	return 0;
}

static void rc_lock(void)
{
	if (mprotect(rc, rc_bytes, PROT_READ) != 0)
		outputerr("deferred_free: ring_control lock failed: "
			  "errno=%d\n", errno);
}

/*
 * One bit per ring slot: 1 == occupied, 0 == free.  Lets enqueue find
 * the next empty slot in O(1) via __builtin_ctzll(~occupied_mask)
 * instead of a linear scan over all 64 entries.  Maintained alongside
 * ring_count: every ptr write that fills a slot sets the bit, every
 * clear that empties a slot clears it.  BSS-resident (not inside the
 * mprotect-bracketed ring), so the cheap scan in enqueue's full-ring
 * check and the ctzll lookup itself need no unlock.  uint64_t suffices
 * because DEFERRED_RING_SIZE == 64; a static_assert would be overkill
 * for a single contiguous file.
 */
static uint64_t occupied_mask;

/*
 * Bracket writers/readers of ring[] with mprotect(): at rest PROT_NONE
 * so a fuzzed value-result stomp SIGSEGVs in copy_from_user instead of
 * scribbling a slot.  ring_unlock() returns a three-way result so ENOMEM
 * (VMA-budget) is distinguishable from generic failure: collapsing them
 * would leave the ring PROT_NONE while the caller fell through, turning
 * queued pages into SEGV_ACCERR bait.  See Documentation/deferred-free.md
 * "Three-result ring_unlock and the mprotect bracket".
 */
enum ring_unlock_result {
	RING_UNLOCK_OK,
	RING_UNLOCK_ENOMEM,
	RING_UNLOCK_FAIL,
};

static enum ring_unlock_result ring_unlock(void)
{
	if (mprotect(ring, ring_bytes, PROT_READ | PROT_WRITE) != 0) {
		int e = errno;

		outputerr("deferred_free: mprotect RW failed: errno=%d\n", e);
		return (e == ENOMEM) ? RING_UNLOCK_ENOMEM : RING_UNLOCK_FAIL;
	}
	return RING_UNLOCK_OK;
}

static void ring_lock(void)
{
	if (mprotect(ring, ring_bytes, PROT_NONE) != 0)
		outputerr("deferred_free: mprotect NONE failed: errno=%d\n", errno);
}

/*
 * Is @ptr currently pinned in the deferred-free ring?  Linear scan of
 * the 64 slots; cheap (64 cache-resident pointer compares) and definitive
 * because ring[] is the source-of-truth for ring residency.
 *
 * The caller must already hold the ring_unlock() bracket: ring[] is
 * PROT_NONE at rest, so an unbracketed read would SIGSEGV.  Splitting
 * the bracket out of this helper lets callers that are already inside
 * an open ring_unlock() window (deferred_free_enqueue_internal's
 * admission-dedup, after the unlock + before the matching ring_lock)
 * skip a second mprotect pair.  Callers that don't already hold the
 * bracket (tracked_free_now) take it themselves before calling.
 */
static bool ring_contains(void *ptr)
{
	unsigned int i;

	for (i = 0; i < DEFERRED_RING_SIZE; i++) {
		if (ring[i].ptr == ptr)
			return true;
	}
	return false;
}

/*
 * Refresh a tracked entry's LRU position (consume + re-insert at head)
 * so long-lived dedup'd anon-pool entries don't rotate out under
 * unrelated tracked-alloc churn.  Skip when @ptr is ring-resident:
 * the ring owns the lifecycle and a fresh alloc_track entry would
 * become a stale survivor that outlives the ring's drain and arms an
 * address-reuse bad-free.  ring_unlock failure -> skip (cannot verify
 * residency safely).  See Documentation/deferred-free.md
 * "alloc_track_refresh" for the full desync analysis.
 */
void alloc_track_refresh(void *ptr)
{
	bool ring_owned = false;
	size_t size;

	if (ptr == NULL)
		return;

	if (ring != NULL) {
		if (ring_unlock() != RING_UNLOCK_OK) {
			__atomic_add_fetch(&shm->stats.deferred_free.alloc_track_refresh_unverified_skip,
					   1, __ATOMIC_RELAXED);
			return;
		}
		ring_owned = ring_contains(ptr);
		ring_lock();
	}

	if (ring_owned) {
		__atomic_add_fetch(&shm->stats.deferred_free.alloc_track_refresh_ring_owned_skip,
				   1, __ATOMIC_RELAXED);
		return;
	}

	/*
	 * Preserve the recorded extent across consume + re-add.  Bump
	 * @ptr's LRU position only on a consume hit (proof it was really
	 * tracked); a miss bails without inserting rather than blessing
	 * an unproven VA and arming a downstream bad-free.  See
	 * Documentation/deferred-free.md "alloc_track_refresh consume-miss
	 * discipline" for the historical bad-free class this replaced.
	 */
	size = alloc_track_lookup_size(ptr);
	if (!alloc_track_consume(ptr)) {
		__atomic_add_fetch(&shm->stats.deferred_free.alloc_track_refresh_consume_miss,
				   1, __ATOMIC_RELAXED);
		return;
	}
	deferred_alloc_track(ptr, size);
}

/*
 * Free-time ownership gate: only a true return from alloc_track_consume()
 * is proof that __zmalloc() currently owns @ptr; a miss swallows the free
 * and bumps a per-site counter for telemetry.  Do NOT gate on
 * alloc_track_lookup() -- it is a value-keyed prefilter that desyncs from
 * the array (rotation / duplicate-ptr edge case).  See
 * Documentation/deferred-free.md "Ownership gate: alloc_track_consume vs
 * alloc_track_lookup" for the historical bad-free class this replaced.
 */
enum tracked_free_site {
	TRACKED_FREE_SITE_RING_EVICT,	/* ring_evict_oldest_safe */
	TRACKED_FREE_SITE_RING_DRAIN,	/* free_ring_entry */
	TRACKED_FREE_SITE_IMMEDIATE,	/* tracked_free_now + enqueue immediate-free fallbacks */
};

static void tracked_free_checked(void *ptr, enum tracked_free_site site)
{
	struct childdata *c;

	if (alloc_track_consume(ptr)) {
		free(ptr);
		return;
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
}

/*
 * Synchronously free a zmalloc_tracked() pointer, skipping when @ptr is
 * ring-resident (the ring owns the free-time consume).  Ring-ownership
 * check scans ring[] directly (source of truth); the previous
 * inflight_hash proxy desynced under ENOMEM and stomp pressure and
 * armed a reuse-mediated double-free.  ring_unlock ENOMEM -> leak @ptr
 * rather than risk it.  See Documentation/deferred-free.md
 * "tracked_free_now ring-residency check".
 */
void tracked_free_now(void *ptr)
{
	bool ring_owned = false;

	if (ptr == NULL)
		return;

	/*
	 * Gate on ring != NULL, not occupied_mask != 0.  occupied_mask
	 * lives in unarmored BSS; a sibling fuzzed value-result syscall
	 * that scribbles it to zero would skip the authoritative ring[]
	 * scan and let this function free() a ring-resident chunk, which
	 * eviction or TTL would then free a second time.  ring is set
	 * once at init and cleared only by ring_dispose_after_enomem();
	 * both writers go through rc_unlock()'s armored bracket, so the
	 * pointer cannot lie about ring liveness.  Always run the armored
	 * ring[] scan whenever the ring still exists.
	 *
	 * Ring residency check runs BEFORE alloc_track_consume:
	 * alloc_track is now populated through ring residency (the
	 * enqueue gate uses non-consuming alloc_track_lookup; consume is
	 * deferred to free_ring_entry / ring_evict_oldest_safe).
	 * Consuming here when the ring owns the ptr would strip the
	 * alloc_track entry the ring's free-time gate relies on -- the
	 * subsequent eviction or drain would see alloc_track_lookup miss
	 * and leak the slot instead of freeing it.  Skip the consume
	 * (and the free, which the ring will perform) when ring-owned.
	 */
	if (ring != NULL) {
		if (ring_unlock() != RING_UNLOCK_OK) {
			__atomic_add_fetch(&shm->stats.deferred_free.tracked_free_unverified_leak,
					   1, __ATOMIC_RELAXED);
			return;
		}
		ring_owned = ring_contains(ptr);
		ring_lock();
	}

	if (ring_owned) {
		__atomic_add_fetch(&shm->stats.deferred_free.ring_owned_skip,
				   1, __ATOMIC_RELAXED);
		return;
	}

	tracked_free_checked(ptr, TRACKED_FREE_SITE_IMMEDIATE);
}

void cleanup_release_post_state(struct syscallrecord *rec)
{
	void *ptr = (void *) rec->post_state;

	rec->post_state = 0;

	if (ptr == NULL)
		return;

	/*
	 * Shape gate first: cheap reject for NULL-ish / non-canonical /
	 * misaligned scribbles.  Forward our caller's PC so per-handler
	 * shape-reject attribution stays sharp.
	 */
	if (looks_like_corrupted_ptr_pc(rec, ptr, __builtin_return_address(0)))
		return;

	/*
	 * Heap-bounds gate: matches the deferred_free_enqueue_internal
	 * reject_outside_heap rail.  Catches scribbles whose value passes
	 * the shape heuristic but lands in the stack / a library mapping /
	 * an executable mapping / one of trinity's own MAP_PRIVATE
	 * regions.  alloc_track_lookup below provides a stronger ground-
	 * truth check, but this rail short-circuits before paying the hash
	 * probe and matches the page-aligned arena-band stomp class the
	 * arena_ptr_stale_caught_post_state telemetry surfaces.  Bumps the
	 * deferred_free_reject_non_heap counter so the rate stays
	 * comparable with the matching enqueue-side reject.
	 */
	if (!is_in_glibc_heap(ptr)) {
		__atomic_add_fetch(&shm->stats.deferred_free.reject_non_heap,
				   1, __ATOMIC_RELAXED);
		return;
	}

	/*
	 * Shared-region overlap gate: matches the
	 * deferred_free_enqueue_internal reject_shared_region rail.  A
	 * scribbled snapshot whose value falls inside one of trinity's own
	 * mmap'd regions (object pool, kcov ring, etc.) is not a free()
	 * target -- libc rejects it as not-malloc()d.  Bumps the matching
	 * counter so the rate is observable alongside the enqueue-side
	 * reject.
	 */
	if (range_overlaps_shared((unsigned long) ptr, 1)) {
		__atomic_add_fetch(&shm->stats.deferred_free.reject_shared_region,
				   1, __ATOMIC_RELAXED);
		return;
	}

	/*
	 * Ownership gate: the shape guard waves through heap-shaped
	 * foreign pointers, so verify @ptr was actually produced by a
	 * zmalloc_tracked() in this child before handing it to free().
	 * A miss is silently leaked -- bounded by child lifetime, vastly
	 * preferable to a glibc/ASAN abort on a foreign address that
	 * would masquerade as a real kernel finding.
	 */
	if (!alloc_track_lookup(ptr))
		return;

	tracked_free_now(ptr);
}

void rec_own(struct syscallrecord *rec, void *ptr)
{
	if (ptr == NULL)
		return;

	/*
	 * Bound: REC_OWNED_MAX is sized so this branch never fires in
	 * practice for in-tree callers (heaviest are ~3 buffers, bound
	 * is 8).  A non-zero overflow rate is a bug to surface, not a
	 * workload to tolerate: log + counter bump so it cannot fail
	 * silently, then fall back to the deferred-free ring so the
	 * caller's "no longer your problem" contract still holds.  The
	 * fallback re-introduces the pre-dispatch ring-enqueue shape the
	 * owned list was built to eliminate -- spec acknowledges and
	 * accepts this trade-off, bounded by the assumption the fallback
	 * is unreachable.
	 */
	if (rec->owned_count >= REC_OWNED_MAX) {
		__atomic_add_fetch(&shm->stats.deferred_free.rec_owned_overflow_to_ring, 1,
				   __ATOMIC_RELAXED);
		outputerr("rec_own: rec->owned[] saturated at %u entries for %s; falling back to deferred_free_enqueue_or_leak\n",
			  REC_OWNED_MAX,
			  rec->entry != NULL ? rec->entry->name : "(unknown)");
		/*
		 * Leak-on-pressure variant: rec_own holds buffers the kernel or
		 * post handler may still consume, so a synchronous free under
		 * ring pressure would be a pre-dispatch UAF.  The overflow is
		 * unreachable in tree today (REC_OWNED_MAX=8, heaviest caller
		 * uses 3) so leak rate is theoretical.
		 */
		deferred_free_enqueue_or_leak(ptr);
		return;
	}

	rec->owned[rec->owned_count++] = ptr;
}

void rec_owned_drain(struct syscallrecord *rec)
{
	unsigned int i;

	if (rec->owned_count == 0)
		return;

	/*
	 * Walk the carrier high-to-low so a longjmp-interrupted drain
	 * leaves a contiguous prefix of still-owned slots and a tail of
	 * cleared (NULL'd, count-decremented) slots.  Critical:
	 * null the slot AND decrement owned_count BEFORE handing the
	 * pointer to tracked_free_now() -- if tracked_free_now() (or a
	 * signal taken during it) longjmps out, a second drain pass on
	 * this rec (or deferred_free_flush() on child exit) sees no
	 * residue and cannot double-free.  Mirrors the "clear the slot
	 * before free" discipline already used by free_ring_entry /
	 * deferred_free_tick on the deferred-free ring itself.
	 */
	for (i = rec->owned_count; i > 0; i--) {
		void *p = rec->owned[i - 1];
		uintptr_t v = (uintptr_t)p;

		/*
		 * Attribution overlay for the SELF-corruption cluster.  If a
		 * sibling scribbled one of the rec->owned[] slots between
		 * enqueue and drain, tracked_free_now(p) below either aborts
		 * inside glibc (heap-check trip) or SIGSEGVs deep in libc, in
		 * either case with the current SREC being this rec (the innocent
		 * drain runs after the culprit's own return) or already-replaced
		 * by whatever cleanup boundary reached the drain.  Log the
		 * pre-free SREC so the child bug-log carries the culprit BEFORE
		 * the glibc abort/SEGV vaporises the state.
		 *
		 * NULL is a legitimate slot value in principle (a caller could
		 * push NULL and rely on tracked_free_now's own NULL handling);
		 * gate the check on p != NULL so a legitimate NULL slot does
		 * not manufacture a false positive.  Same [0x10000, 2^47)
		 * bracket the always-on shape heuristic uses.  Log-only:
		 * tracked_free_now(p) still runs unchanged.
		 */
		if (unlikely(p != NULL &&
			     !(v >= 0x10000UL && v < 0x800000000000UL))) {
			struct childdata *cc = this_child();

			log_self_corrupt_culprit(
				"deferred:rec_owned_drain", v,
				cc != NULL ? &cc->syscall : NULL);
		}

		rec->owned[i - 1] = NULL;
		rec->owned_count = i - 1;
		tracked_free_now(p);
	}
}

/*
 * Per-process kernel VMA budget, read once from
 * /proc/sys/vm/max_map_count at parent init and inherited by every
 * forked child via COW BSS.  The soft cap below (see
 * deferred_free_enqueue) compares the in-ring entry count against
 * g_max_vmas/2 to keep deferred-free's contribution to address-space
 * pressure under half the per-process budget.  Default value
 * (DEFERRED_DEFAULT_MAX_VMAS) is the Linux 6.x default for
 * vm.max_map_count -- used if the procfs read fails for any reason
 * (containers without /proc/sys mounted, sysctl read denied, etc.)
 * so the bound still has a sane ceiling rather than firing on every
 * enqueue (which would happen if g_max_vmas were left at zero).
 */
#define DEFERRED_DEFAULT_MAX_VMAS	65536U
static unsigned int g_max_vmas = DEFERRED_DEFAULT_MAX_VMAS;

/*
 * Tear down the ring after ring_unlock() ENOMEM: munmap releases the
 * VMA (dropping the PROT_NONE SEGV_ACCERR bait) at the cost of leaking
 * still-queued ptrs until child exit.  Untrack the shared region BEFORE
 * munmap (check-static pairing rule).  Idempotent (ring==NULL bail);
 * after dispose the deferred-free machinery is functionally off in this
 * child for the rest of its life.  See Documentation/deferred-free.md
 * "ring_dispose_after_enomem" for the tradeoff analysis.
 */
static void ring_dispose_after_enomem(void)
{
	if (ring == NULL)
		return;

	untrack_shared_region((unsigned long)ring, ring_bytes);
	if (munmap(ring, ring_bytes) != 0)
		outputerr("deferred_free: munmap ring after ENOMEM failed: errno=%d\n",
			  errno);

	if (rc_unlock() == 0) {
		ring = NULL;
		ring_count = 0;
		rc_lock();
	}
	occupied_mask = 0;
	if (inflight_unlock() == 0) {
		memset(inflight_hash, 0, inflight_hash_bytes);
		inflight_lock();
	}
}

static void deferred_free_read_max_map_count(void)
{
	int fd;
	char buf[32];
	ssize_t n;
	long v;

	fd = open("/proc/sys/vm/max_map_count", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		outputerr("deferred_free: open(/proc/sys/vm/max_map_count) "
			  "failed: %s; using default %u\n",
			  strerror(errno), g_max_vmas);
		return;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	(void)close(fd);
	if (n <= 0) {
		outputerr("deferred_free: read(/proc/sys/vm/max_map_count) "
			  "returned %zd; using default %u\n", n, g_max_vmas);
		return;
	}
	buf[n] = '\0';
	v = strtol(buf, NULL, 10);
	if (v > 0 && v <= INT_MAX)
		g_max_vmas = (unsigned int)v;
}

/*
 * CAS the cross-fleet outstanding-VMA high-water mark up to @v.
 * Up-only so a quiet trailing window after a peak doesn't erase the
 * peak.  RELAXED ordering: the counter is observability, not a
 * synchronisation primitive.
 */
static void deferred_free_record_outstanding(unsigned int v)
{
	unsigned long cur = __atomic_load_n(&shm->stats.deferred_free.outstanding_vmas,
					    __ATOMIC_RELAXED);

	while (v > cur) {
		if (__atomic_compare_exchange_n(
				&shm->stats.deferred_free.outstanding_vmas,
				&cur, (unsigned long)v, false,
				__ATOMIC_RELAXED, __ATOMIC_RELAXED))
			return;
	}
}

void deferred_free_init(void)
{
	const size_t raw = sizeof(struct deferred_entry) * DEFERRED_RING_SIZE;
	const size_t inflight_raw = sizeof(void *) * INFLIGHT_HASH_SIZE;
	const size_t at_raw = sizeof(void *) *
		(ALLOC_TRACK_SIZE + ALLOC_TRACK_HASH_SIZE) +
		sizeof(size_t) * ALLOC_TRACK_SIZE;
	const size_t rc_raw = sizeof(struct ring_control);

	/*
	 * Ring control armor page first -- writes to ring/ring_bytes/
	 * ring_count below all go through rc->* fields, so the page must
	 * be live and writable for the duration of init.  Locked to
	 * PROT_READ at the tail of init alongside the data ring.
	 */
	rc_bytes = ((rc_raw + page_size - 1) / page_size) * page_size;
	rc = mmap(NULL, rc_bytes, PROT_READ | PROT_WRITE,
		  MAP_PRIVATE | MAP_ANON, -1, 0);
	if (rc == MAP_FAILED) {
		outputerr("deferred_free_init: ring_control mmap %zu failed\n",
			  rc_bytes);
		exit(EXIT_FAILURE);
	}
	memset(rc, 0, rc_bytes);
	track_shared_region((unsigned long)rc, rc_bytes);

	ring_bytes = ((raw + page_size - 1) / page_size) * page_size;

	ring = mmap(NULL, ring_bytes, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANON, -1, 0);
	if (ring == MAP_FAILED) {
		outputerr("deferred_free_init: mmap %zu failed\n", ring_bytes);
		exit(EXIT_FAILURE);
	}
	memset(ring, 0, ring_bytes);
	track_shared_region((unsigned long)ring, ring_bytes);
	ring_count = 0;
	occupied_mask = 0;
	ring_lock();
	rc_lock();

	/*
	 * inflight_hash backing lives in its own mmap'd region so the
	 * mm-syscall sanitisers refuse fuzzed pointers/lengths that would
	 * alias the membership-set pages, and so writers can bracket the
	 * RW window with mprotect() the same way ring[] does.  Steady
	 * state is PROT_READ -- the contains() hot path reads directly
	 * without an mprotect bracket.  See the storage comment above
	 * INFLIGHT_HASH_SHIFT for the threat model.
	 */
	inflight_hash_bytes = ((inflight_raw + page_size - 1) / page_size) *
			      page_size;
	inflight_hash = mmap(NULL, inflight_hash_bytes,
			     PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANON, -1, 0);
	if (inflight_hash == MAP_FAILED) {
		outputerr("deferred_free_init: inflight_hash mmap %zu "
			  "failed\n", inflight_hash_bytes);
		exit(EXIT_FAILURE);
	}
	memset(inflight_hash, 0, inflight_hash_bytes);
	track_shared_region((unsigned long)inflight_hash, inflight_hash_bytes);
	inflight_lock();

	/*
	 * alloc_track[] and alloc_track_hash[] share one mmap'd region so a
	 * single mprotect bracket covers both for deferred_alloc_track's
	 * combined slot+hash write.  PROT_READ steady state keeps the lookup
	 * hot path (alloc_track_lookup, called from every deferred-free
	 * enqueue ownership gate and from every cleanup_release_post_state)
	 * free of mprotect syscalls -- only the writer paths flip RW.
	 */
	alloc_track_bytes = ((at_raw + page_size - 1) / page_size) * page_size;
	alloc_track_base = mmap(NULL, alloc_track_bytes,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANON, -1, 0);
	if (alloc_track_base == MAP_FAILED) {
		outputerr("deferred_free_init: alloc_track mmap %zu failed\n",
			  alloc_track_bytes);
		exit(EXIT_FAILURE);
	}
	memset(alloc_track_base, 0, alloc_track_bytes);
	alloc_track = (void **)alloc_track_base;
	alloc_track_hash = alloc_track + ALLOC_TRACK_SIZE;
	alloc_track_sizes = (size_t *)(alloc_track_hash + ALLOC_TRACK_HASH_SIZE);
	track_shared_region((unsigned long)alloc_track_base, alloc_track_bytes);
	alloc_track_lock();

	/*
	 * Read vm.max_map_count once in the parent so every child
	 * inherits the same cached value via COW BSS.  Failure to read
	 * is non-fatal: the default DEFERRED_DEFAULT_MAX_VMAS leaves
	 * the soft cap at half the upstream default, which is
	 * conservative without being trigger-happy.
	 */
	deferred_free_read_max_map_count();

	/*
	 * Cache the brk-arena extent and labeled non-brk allocator
	 * regions now, before any child forks.  Every child inherits
	 * the bounds via COW BSS as a baseline, then re-parses
	 * /proc/self/maps once at end-of-init_child() to capture the
	 * mmap arenas glibc spawned post-fork.  Caching at init time
	 * (here and at child startup, not per call) keeps the hot
	 * is_in_glibc_heap / range_overlaps_libc_heap path a small
	 * array walk -- a syscall fuzzer parsing /proc on every
	 * deferred_free_enqueue would dwarf the work it's gating.
	 */
	heap_bounds_init();
}

/*
 * Alignment is non-negotiable.  glibc malloc returns >= 8-byte
 * aligned chunks on x86_64, so a free() candidate with low bits set
 * cannot be a real allocation start.  libasan internally CHECKs
 * alignment in its poisoning path (asan_poisoning.cpp:
 * "AddrIsAlignedByGranularity(addr) != 0") and aborts the child on
 * the misaligned address before its bad-free reporter ever runs --
 * the cluster shows up as a CHECK-failed crash without an ASAN
 * report attached, which is harder to triage than a normal bad-free.
 */
static bool deferred_free_reject_misaligned(void *ptr, void *caller_pc)
{
	static unsigned long misalign_drops;
	unsigned long n;

	if (((unsigned long)ptr & 0x7) == 0)
		return false;

	n = ++misalign_drops;
	if ((n % 1000) == 1) {
		char pcbuf[128];
		outputerr("deferred_free_enqueue: rejected misaligned "
			  "ptr=%p caller=%s [%lu cumulative]\n", ptr,
			  pc_to_string(caller_pc, pcbuf, sizeof(pcbuf)), n);
	}
	__atomic_add_fetch(&shm->stats.deferred_free.reject_misaligned, 1, __ATOMIC_RELAXED);
	return true;
}

/*
 * Reject pid-scribbled / canonical-out-of-range / misaligned values
 * BEFORE they ever reach the ring.  Bug class: a sibling fuzzed
 * value-result syscall scribbles a tid/pid into rec->aN, the post
 * handler does
 * deferred_freeptr(&rec->aN) which arrives here, and N syscalls
 * later deferred_free_tick() free()s the pid -- SIGSEGV with
 * si_addr==si_pid.  Drop the bad value at the post-handler boundary
 * (one counter bumped, ring slot stays empty) instead of letting
 * the corruption propagate into the ring.
 */
static bool deferred_free_reject_corrupt_shape(void *ptr, void *caller_pc)
{
	if (!is_corrupt_ptr_shape(ptr))
		return false;

	outputerr("deferred_free_enqueue: rejected suspicious ptr=%p "
		  "(pid-scribbled?)\n", ptr);
	deferred_free_reject_bump(caller_pc);
	__atomic_add_fetch(&shm->stats.deferred_free.reject_corrupt_shape, 1, __ATOMIC_RELAXED);
	return true;
}

/*
 * Heap-bounds backstop: every pointer __zmalloc() can hand back
 * lives inside the brk arena cached at init time.  A scribbled
 * snapshot/arg slot whose value passes the shape heuristic above
 * but lands in the stack, an mmap'd library, an executable
 * mapping, or one of trinity's own MAP_PRIVATE regions cannot be
 * a real malloc result -- free()ing it is undefined.  Two
 * compares, branch-predictable, no syscalls; cheaper than the
 * O(N) alloc-track scan below and catches the case where the
 * stomp value coincidentally matches a recently-evicted ring
 * slot the alloc-track ring no longer remembers.
 */
static bool deferred_free_reject_outside_heap(void *ptr, void *caller_pc)
{
	static unsigned long non_heap_drops;
	unsigned long n;
	struct childdata *c;

	if (is_in_glibc_heap(ptr))
		return false;

	n = ++non_heap_drops;
	if ((n % 1000) == 1) {
		char pcbuf[128];
		outputerr("deferred_free_enqueue: rejected ptr=%p "
			  "(outside glibc heap) caller=%s "
			  "[%lu cumulative]\n", ptr,
			  pc_to_string(caller_pc, pcbuf, sizeof(pcbuf)), n);
	}
	c = this_child();
	if (c != NULL && c->stats_ring != NULL)
		stats_ring_enqueue(c->stats_ring,
				   STATS_FIELD_SNAPSHOT_NON_HEAP_REJECT,
				   0, 1);
	else
		parent_stats.snapshot_non_heap_reject++;
	__atomic_add_fetch(&shm->stats.deferred_free.reject_non_heap, 1, __ATOMIC_RELAXED);
	return true;
}

/* Force-free the oldest (lowest TTL) entry to make room.  In
 * practice this rarely happens — TTL range is 5-50 and we tick every
 * syscall. */
static void ring_evict_oldest_safe(void)
{
	unsigned int i;
	unsigned int oldest = 0;
	unsigned int min_ttl = UINT_MAX;
	void *evict_ptr;
	bool corrupt = false;

	for (i = 0; i < DEFERRED_RING_SIZE; i++) {
		if (ring[i].ptr != NULL && ring[i].ttl < min_ttl) {
			min_ttl = ring[i].ttl;
			oldest = i;
		}
	}
	if (ring[oldest].ptr == NULL)
		return;

	evict_ptr = ring[oldest].ptr;

	/*
	 * Interim leak-on-eviction defense: this site does NOT free()
	 * the evicted chunk.  Reclaim the slot, drop the inflight-hash
	 * entry, bump ring_evict_leaked; the heap chunk leaks until
	 * child exit.  alloc_track intentionally left populated (chunk
	 * is still live from the heap's view).  Prefilters run for
	 * telemetry granularity (ring_eviction_corrupt).  See
	 * Documentation/deferred-free.md "Leak-on-eviction defense"
	 * for the address-reuse bad-free class this closes.
	 */
	if (!is_in_glibc_heap(evict_ptr) ||
	    range_overlaps_shared((unsigned long)evict_ptr, 1))
		corrupt = true;
	if (corrupt) {
		struct childdata *c = this_child();

		if (c != NULL && c->stats_ring != NULL)
			stats_ring_enqueue(c->stats_ring,
					   STATS_FIELD_RING_EVICTION_CORRUPT,
					   0, 1);
		else
			parent_stats.ring_eviction_corrupt++;
	} else {
		inflight_hash_remove(evict_ptr);
		__atomic_add_fetch(&shm->stats.deferred_free.ring_evict_leaked,
				   1, __ATOMIC_RELAXED);
	}
	ring[oldest].ptr = NULL;
	occupied_mask &= ~(1ULL << oldest);
	if (rc_unlock() == 0) {
		ring_count--;
		rc_lock();
	}
}

/*
 * Shared implementation for deferred_free_enqueue() and
 * deferred_free_enqueue_or_leak().  The full reject / admit pipeline
 * is identical for the two entry points; only the five
 * under-pressure fallback paths branch on @leak_on_pressure.  On a
 * leak path the caller's contract is "the buffer survives until
 * child exit"; the heap chunk is not free()d, the alloc-track slot
 * is intentionally left populated so a later tracked_free_now /
 * deferred_free_enqueue on the same ptr still recognises it as
 * owned, and the kernel reclaims the address space when the child
 * exits.
 *
 * The reject paths above the fallback bracket free nothing in either
 * variant -- a rejected pointer either was never a real allocation
 * (shape / heap-bounds / untracked) or is being intentionally held
 * out of the queue (shared-region overlap); both classes pass the
 * pointer back to the caller unchanged.
 */
static void deferred_free_enqueue_internal(void *ptr, void *caller_pc,
					   bool leak_on_pressure)
{
	unsigned int i;

	if (ptr == NULL)
		return;

	if (deferred_free_reject_misaligned(ptr, caller_pc))
		return;

	if (deferred_free_reject_corrupt_shape(ptr, caller_pc))
		return;

	if (deferred_free_reject_outside_heap(ptr, caller_pc))
		return;

	/*
	 * Ground-truth check: refuse to enqueue a pointer that __zmalloc()
	 * never produced.  Catches the bad-free class where a sibling stomp
	 * (or kernel write into a mistakenly-aliased rec field) overwrites
	 * a snapshot/arg slot with a heap-region-shaped value that defeats
	 * the heuristic guard above.  Eight ASAN bad-frees in a recent run
	 * all matched this shape: 8-byte aligned, in user VA, sitting inside
	 * the heap arena, but not at any malloc-returned offset.
	 *
	 * Non-consuming probe: the alloc_track entry is left in place so it
	 * remains the authoritative ownership gate at actual-free time
	 * (free_ring_entry / ring_evict_oldest_safe).  Defer of the consume
	 * is what lets a stomp that swaps ring[i].ptr to an interior or
	 * stale heap-shaped value be rejected at free time -- the interior
	 * pointer hashes to a different slot, alloc_track_lookup misses,
	 * and the slot is leaked instead of handed to free().  The
	 * companion free-time consume is in free_ring_entry and
	 * ring_evict_oldest_safe.
	 */
	if (!alloc_track_lookup(ptr)) {
		static unsigned long unknown_drops;
		unsigned long n = ++unknown_drops;
		if ((n % 1000) == 1) {
			char pcbuf[128];
			outputerr("deferred_free_enqueue: rejected ptr=%p "
				  "(not a tracked allocation) caller=%s "
				  "[%lu cumulative]\n", ptr,
				  pc_to_string(caller_pc, pcbuf, sizeof(pcbuf)), n);
		}
		deferred_free_reject_bump(caller_pc);
		__atomic_add_fetch(&shm->stats.deferred_free.reject_untracked, 1, __ATOMIC_RELAXED);
		return;
	}

	/*
	 * Refuse to enqueue a pointer that lands inside one of trinity's
	 * own mmap'd shared regions.  ASAN catches these as bad-free
	 * (libasan: "attempting free on address which was not malloc()-ed"),
	 * non-ASAN runs silently corrupt the glibc allocator.  Either way
	 * the underlying bug is some arg generator handing back a tracked-
	 * mmap pointer for an arg slot whose argtype (PATHNAME, IOVEC,
	 * SOCKADDR) generic_free_arg expects to be heap-allocated.
	 *
	 * Logging the caller PC so we can still find the offending
	 * generator -- the guard fixes the symptom but the rejection log
	 * is the breadcrumb to the root cause.  Limited to one print per
	 * 1000 rejects to keep noise sane.
	 *
	 * This range check runs BEFORE ring_unlock() so we don't pay the
	 * mprotect cost on rejected enqueues.
	 */
	if (range_overlaps_shared((unsigned long)ptr, 1)) {
		static unsigned long rejects;
		unsigned long n = ++rejects;
		if ((n % 1000) == 1) {
			char pcbuf[128];
			outputerr("deferred_free_enqueue: rejected ptr=%p "
				  "(overlaps shared region) caller=%s "
				  "[%lu cumulative]\n", ptr,
				  pc_to_string(caller_pc, pcbuf, sizeof(pcbuf)), n);
		}
		__atomic_add_fetch(&shm->stats.deferred_free.reject_shared_region, 1, __ATOMIC_RELAXED);
		return;
	}

	/*
	 * Soft cap on the per-process VMA contribution of the deferred-
	 * free path.  Each in-ring entry pins an allocation past its
	 * natural lifetime, holding the matching glibc-arena page (and
	 * any redzone VMA a future hardening pass might wrap around it)
	 * resident; bounding the in-flight count at half of
	 * /proc/sys/vm/max_map_count leaves the other half for the
	 * fuzzer's actual mm-syscall workload.  With the current
	 * DEFERRED_RING_SIZE of 64 the cap is non-binding under any
	 * default max_map_count (32768+), but stays correct on systems
	 * tuned down and would limit a future per-slot redzone variant.
	 *
	 * Placed AFTER the alloc_track_lookup ownership gate so an
	 * untracked-ptr reject short-circuits before the VMA accounting,
	 * and BEFORE ring_unlock so the rejected enqueue does not pay
	 * the mprotect bracket cost.  The alloc_track entry stays
	 * populated through ring residency by design (consume is
	 * deferred to free_ring_entry / ring_evict_oldest_safe); the
	 * pressure-path immediate-free below routes around the ring and
	 * goes through tracked_free_checked() so its free() is gated on
	 * alloc_track_consume() success -- keeps the set in lock-step
	 * with the heap, and a consume-miss (lookup said yes earlier but
	 * the slot has since rotated out) bumps deferred_free_reject_
	 * untracked instead of being silently freed.
	 */
	if (ring_count > g_max_vmas / 2) {
		__atomic_add_fetch(&shm->stats.deferred_free.vma_fallback_immediate,
				   1, __ATOMIC_RELAXED);
		if (leak_on_pressure) {
			__atomic_add_fetch(&shm->stats.deferred_free.pre_dispatch_leaked,
					   1, __ATOMIC_RELAXED);
		} else {
			tracked_free_checked(ptr,
					     TRACKED_FREE_SITE_IMMEDIATE);
		}
		return;
	}

	/*
	 * Ring was disposed by a prior ENOMEM event (enqueue or drain
	 * path).  Deferred-free is off for the rest of this child's life;
	 * fall through to immediate free() instead of mprotect-thrashing
	 * on a NULL ring.  No counter bump: the dispose-event counters
	 * (_enomem_drain, _rw_restore_enomem) already record the rate of
	 * ring teardowns; per-enqueue noise after teardown adds nothing.
	 */
	if (ring == NULL) {
		if (leak_on_pressure) {
			__atomic_add_fetch(&shm->stats.deferred_free.pre_dispatch_leaked,
					   1, __ATOMIC_RELAXED);
		} else {
			tracked_free_checked(ptr,
					     TRACKED_FREE_SITE_IMMEDIATE);
		}
		return;
	}

	/*
	 * RING_UNLOCK_ENOMEM is the hard cap -- the kernel just told us
	 * it can't satisfy a VMA split for the protection change.  Dispose
	 * the ring entirely (munmap releases the VMA slot so the page
	 * stops being SEGV_ACCERR fault-bait for sibling fuzzed value-
	 * result syscalls), bump the dedicated counter (the existing
	 * outputerr line from ring_unlock keeps the per-event log
	 * breadcrumb), and free this ptr immediately so the caller's "no
	 * longer your problem" contract still holds (or leak it instead
	 * for the pre-dispatch variant -- see leak_on_pressure docs).
	 *
	 * Setting a sticky drain-aggressive latch and letting the next
	 * tick chew through the ring instead would leave every queued
	 * ptr's PROT_NONE page persistent in the meantime -- exactly the
	 * SEGV_ACCERR fault-bait residue this path must avoid.  Dispose
	 * drops the page outright, so the latch infrastructure is gone
	 * (no consumer left to set it to true).
	 *
	 * RING_UNLOCK_FAIL (any other errno) falls through to the same
	 * immediate-free / leak path, but does NOT dispose the ring -- a
	 * non-ENOMEM failure is a different class (typically EACCES from
	 * a not-yet-sanitised mm-syscall that overlapped the ring), not
	 * a VMA-budget event, and the next ring_unlock can plausibly
	 * succeed.
	 */
	{
		enum ring_unlock_result r = ring_unlock();

		if (r == RING_UNLOCK_ENOMEM) {
			__atomic_add_fetch(&shm->stats.deferred_free.enomem_drain,
					   1, __ATOMIC_RELAXED);
			ring_dispose_after_enomem();
			if (leak_on_pressure) {
				__atomic_add_fetch(&shm->stats.deferred_free.pre_dispatch_leaked,
						   1, __ATOMIC_RELAXED);
			} else {
				tracked_free_checked(ptr,
						     TRACKED_FREE_SITE_IMMEDIATE);
			}
			return;
		}
		if (r != RING_UNLOCK_OK) {
			if (leak_on_pressure) {
				__atomic_add_fetch(&shm->stats.deferred_free.pre_dispatch_leaked,
						   1, __ATOMIC_RELAXED);
			} else {
				tracked_free_checked(ptr,
						     TRACKED_FREE_SITE_IMMEDIATE);
			}
			return;
		}
	}

	/*
	 * Admission dedup: refuse to take a second slot for a ptr that
	 * already owns one.  alloc_track_lookup() above does not know
	 * about ring residency, and with consume deferred to free time
	 * the same ptr remains alloc_track-resident for the duration of
	 * its ring lifetime -- two back-to-back enqueues of the same ptr
	 * would both pass the lookup gate.  Two slots holding the same
	 * value is the reuse-mediated double-free shape: slot A's TTL
	 * fires and free()s @ptr; the address is reused by a new alloc;
	 * slot B's TTL fires and free()s the new owner's chunk.  ring[]
	 * is the source-of-truth, so scan it directly.  The ring_unlock
	 * bracket above is still open, so this is just a 64-compare
	 * scan, no additional mprotect.  Re-lock and bail on hit.
	 */
	if (ring_contains(ptr)) {
		ring_lock();
		__atomic_add_fetch(&shm->stats.deferred_free.double_admit_skip,
				   1, __ATOMIC_RELAXED);
		return;
	}

	if (occupied_mask == ~0ULL)
		ring_evict_oldest_safe();

	/*
	 * Ring is logically full but the full-ring eviction above found
	 * nothing evictable (every slot's ptr was scribbled to NULL by a
	 * fuzzed value-result syscall).  The tick-loop reconciliation
	 * will catch up; for this call, re-lock the ring and fall back to
	 * a plain free (or a leak for the pre-dispatch variant) so we
	 * don't ctzll(0) into UB territory and write one element past
	 * the ring.
	 */
	if (occupied_mask == ~0ULL) {
		ring_lock();
		if (leak_on_pressure) {
			__atomic_add_fetch(&shm->stats.deferred_free.pre_dispatch_leaked,
					   1, __ATOMIC_RELAXED);
		} else {
			tracked_free_checked(ptr,
					     TRACKED_FREE_SITE_IMMEDIATE);
		}
		return;
	}

	/* Find an empty slot.  After the full-ring eviction above, at
	 * least one bit in occupied_mask is clear, so ~occupied_mask is
	 * non-zero and __builtin_ctzll's UB-on-zero case can't fire. */
	i = __builtin_ctzll(~occupied_mask);
	ring[i].ptr = ptr;
	ring[i].ttl = RAND_RANGE(DEFERRED_TTL_MIN, DEFERRED_TTL_MAX);
	occupied_mask |= 1ULL << i;
	if (rc_unlock() == 0) {
		ring_count++;
		rc_lock();
	}
	deferred_free_record_outstanding(ring_count);

	ring_lock();

	/*
	 * Record this admission in the in-flight set.  Outside both the
	 * ring_unlock bracket and the rc_unlock bracket -- inflight_hash
	 * has its own armor page and its own RW window.
	 */
	inflight_hash_insert(ptr);
}

void deferred_free_enqueue(void *ptr)
{
	deferred_free_enqueue_internal(ptr, __builtin_return_address(0), false);
}

void deferred_free_enqueue_or_leak(void *ptr)
{
	deferred_free_enqueue_internal(ptr, __builtin_return_address(0), true);
}

void deferred_freeptr(unsigned long *p)
{
	void *ptr = (void *) *p;
	*p = 0;
	deferred_free_enqueue(ptr);
}

/*
 * Free one ring entry's payload, dropping it if the pointer fails the
 * sanity bands.  Both tick (TTL expiry) and flush (child exit) route
 * through here so a scribbled ring entry cannot silently reach free()
 * via flush.  Caller MUST clear ring[slot].ptr (and decrement
 * ring_count where per-slot) before calling -- a signal that longjmps
 * mid-free must not leave a freed ptr pending in the ring.  Re-runs the
 * enqueue-time stateless gates (shape / heap-bounds / shared-region);
 * binding ownership gate is alloc_track_consume via
 * tracked_free_checked.  Clean path removes from inflight_hash.  See
 * Documentation/deferred-free.md "free_ring_entry corruption gating".
 */
static void free_ring_entry(void *ptr, unsigned int slot)
{
	struct childdata *c;
	const char *reason = NULL;

	if (is_corrupt_ptr_shape(ptr))
		reason = "shape";
	else if (!is_in_glibc_heap(ptr))
		reason = "non-heap";
	else if (range_overlaps_shared((unsigned long)ptr, 1))
		reason = "shared-region";

	if (reason != NULL) {
		c = this_child();
		outputerr("deferred_free: rejected ptr=%p in slot %u (%s)\n",
			  ptr, slot, reason);
		if (c != NULL && c->stats_ring != NULL)
			stats_ring_enqueue(c->stats_ring,
					   STATS_FIELD_DEFERRED_FREE_CORRUPT_PTR,
					   0, 1);
		else
			parent_stats.deferred_free_corrupt_ptr++;
		return;
	}

	inflight_hash_remove(ptr);
	tracked_free_checked(ptr, TRACKED_FREE_SITE_RING_DRAIN);
}

/*
 * Periodic garbage collection of orphaned in-flight entries.
 *
 * In-ring stomps can swap a ring slot's ptr to some other value before
 * the drain fires.  When the drain reaches that slot, free_ring_entry's
 * alloc-track ownership gate sees the stomped value (not the originally
 * admitted ptr), rejects it, and leaves the original ptr's entry in
 * inflight_hash[] -- we have no way to recover the original value to
 * call inflight_hash_remove on it.  The eviction path leaves the same
 * residue on a stomp.  Over a long run those orphans accumulate; left
 * unbounded they would saturate the 1024-slot set and degrade probe
 * length.  Two stomps per orphan are required (one to displace, one
 * never restored), so growth is slow -- prior runs observed ~1 stomp/h
 * -- but the sweep keeps the set bounded regardless.
 *
 * Two-pass to avoid iterating across the shift-back rearrangement that
 * inflight_hash_remove() performs: pass 1 collects ptrs whose presence
 * in the set does not match a slot in ring[]; pass 2 removes them.  The
 * stack-local orphans[] array is bounded by INFLIGHT_HASH_SIZE so the
 * collect pass cannot overflow.
 *
 * Caller must hold ring_unlock() because we read ring[i].ptr.  Cost is
 * O(N_inflight * DEFERRED_RING_SIZE) plus the removal walks -- ~65K
 * compares worst case, well under a millisecond on contemporary CPUs.
 */
static void inflight_gc_sweep(void)
{
	void *orphans[INFLIGHT_HASH_SIZE];
	unsigned int n_orphans = 0;
	unsigned int idx, i;

	for (idx = 0; idx < INFLIGHT_HASH_SIZE; idx++) {
		void *ptr = inflight_hash[idx];
		bool in_ring = false;

		if (ptr == NULL)
			continue;

		for (i = 0; i < DEFERRED_RING_SIZE; i++) {
			if (ring[i].ptr == ptr) {
				in_ring = true;
				break;
			}
		}
		if (!in_ring)
			orphans[n_orphans++] = ptr;
	}

	for (i = 0; i < n_orphans; i++)
		inflight_hash_remove(orphans[i]);

	if (n_orphans > 0)
		outputerr("deferred_free: gc swept %u in-flight orphans\n",
			  n_orphans);
}

/*
 * Run the GC sweep every INFLIGHT_GC_INTERVAL batched-tick bodies.
 * 1024 * DEFERRED_TICK_BATCH = ~16K syscalls between sweeps; with
 * stomps observed at ~1/h, the 1024-slot set has weeks of headroom,
 * but the bounded cadence keeps the growth rate independent of how
 * long a fuzz run actually runs.
 */
#define INFLIGHT_GC_INTERVAL	1024

void deferred_free_tick(void)
{
	static unsigned int tick_count;
	static unsigned int gc_count;
	unsigned int i;
	enum ring_unlock_result r;

	/* Cheap path: ring_count is read while still locked, but it lives
	 * in BSS (not in the protected ring), so this access is safe.
	 * ring_count is also zero when the ring has been disposed after
	 * an ENOMEM event, so this guard doubles as the ring==NULL bail. */
	if (ring_count == 0)
		return;

	/*
	 * Batch ticks: run the full mprotect+walk+free bracket only on
	 * 1-in-DEFERRED_TICK_BATCH calls.  The other calls bail here
	 * without taking the mprotect bracket -- ~7x reduction in
	 * mprotect syscalls (and matching TLB-shootdown traffic across
	 * sibling fuzz children).  See DEFERRED_TICK_BATCH comment for
	 * the TTL-multiplier side effect.
	 *
	 * tick_count is BSS-resident (not in the ring), and per-child by
	 * fork's COW, so this static is safe to touch without unlocking.
	 */
	if ((++tick_count & (DEFERRED_TICK_BATCH - 1)) != 0)
		return;

	/*
	 * ENOMEM on the RW-restore is the same VMA-exhaustion class the
	 * enqueue path handles, just observed from the drain side: the
	 * kernel cannot satisfy a split for the protection change.
	 * Leaving the ring at PROT_NONE here turns the page into
	 * fault-bait for sibling fuzzed value-result syscalls, and the
	 * next tick hits the same ENOMEM and emits another "mprotect RW
	 * failed" line.  Dispose the ring outright so the PROT_NONE
	 * residue goes away; the entries currently queued are leaked
	 * (lost forever from glibc's tracking until the child exits),
	 * which is the worst case of the drain-aggressive tradeoff --
	 * acceptable because the alternative is the loop above
	 * continuing to thrash for the rest of the run.
	 *
	 * RING_UNLOCK_FAIL (any other errno) keeps the prior behaviour:
	 * bail this tick, leave the page PROT_NONE, and retry on the
	 * next tick.  A transient EACCES from a not-yet-sanitised mm-
	 * syscall is not the VMA-budget class and does not warrant
	 * abandoning the ring.
	 */
	r = ring_unlock();
	if (r == RING_UNLOCK_ENOMEM) {
		__atomic_add_fetch(&shm->stats.deferred_free.rw_restore_enomem,
				   1, __ATOMIC_RELAXED);
		ring_dispose_after_enomem();
		return;
	}
	if (r != RING_UNLOCK_OK)
		return;

	/*
	 * Hoist the ring_control bracket around the whole drain loop:
	 * every ring_count-- inside the loop runs at PROT_READ|WRITE
	 * without a per-iteration mprotect pair, and locks back to
	 * PROT_READ once the loop has settled.  Bail before touching
	 * ring_count if the unlock fails -- the next tick will retry.
	 */
	if (rc_unlock() != 0) {
		ring_lock();
		return;
	}

	for (i = 0; i < DEFERRED_RING_SIZE; i++) {
		void *ptr;

		if (ring[i].ptr == NULL) {
			/*
			 * Stomped corpse: a fuzzed value-result syscall
			 * scribbled this slot's ptr to NULL while it was
			 * still marked occupied.  Reconcile the bookkeeping
			 * so occupied_mask and ring_count track reality;
			 * otherwise accumulated stomps drive occupied_mask
			 * to ~0ULL and the enqueue path's __builtin_ctzll
			 * lands on UB.
			 */
			if (occupied_mask & (1ULL << i)) {
				occupied_mask &= ~(1ULL << i);
				ring_count--;
			}
			continue;
		}

		if (ring[i].ttl > 0) {
			ring[i].ttl--;
			continue;
		}

		/* TTL expired — free it.  Clear the slot BEFORE calling
		 * the free function so that if a signal interrupts us
		 * mid-free and we longjmp, the slot is already empty. */
		ptr = ring[i].ptr;
		ring[i].ptr = NULL;
		occupied_mask &= ~(1ULL << i);
		ring_count--;

		free_ring_entry(ptr, i);
	}

	rc_lock();

	if ((++gc_count & (INFLIGHT_GC_INTERVAL - 1)) == 0)
		inflight_gc_sweep();

	ring_lock();
}

void deferred_free_flush(void)
{
	unsigned int i;
	enum ring_unlock_result r;

	/* Ring already disposed by a prior ENOMEM event.  Nothing to
	 * flush; skip ring_unlock so we don't emit a "mprotect RW
	 * failed" log line on every child exit for the rest of the run. */
	if (ring == NULL)
		return;

	/*
	 * Called from the child exit path.  ENOMEM still warrants the
	 * dispose treatment: the child is going away anyway, but its
	 * teardown can run for many syscalls (atexit handlers, glibc
	 * arena cleanup), during which a PROT_NONE ring page is still
	 * fault-bait for any sibling whose fuzzed value-result buffer
	 * lands inside.  Dispose drops the page; the queued ptrs leak
	 * for the brief teardown window, then the kernel reaps the
	 * whole address space at exit.  RING_UNLOCK_FAIL (non-ENOMEM)
	 * stays a silent bail -- not the VMA-budget class.
	 */
	r = ring_unlock();
	if (r == RING_UNLOCK_ENOMEM) {
		__atomic_add_fetch(&shm->stats.deferred_free.rw_restore_enomem,
				   1, __ATOMIC_RELAXED);
		ring_dispose_after_enomem();
		return;
	}
	if (r != RING_UNLOCK_OK)
		return;

	for (i = 0; i < DEFERRED_RING_SIZE; i++) {
		void *ptr;

		if (ring[i].ptr == NULL)
			continue;

		/* Clear before invoking, mirroring tick: a signal that
		 * longjmps mid-free leaves the slot empty either way. */
		ptr = ring[i].ptr;
		ring[i].ptr = NULL;
		free_ring_entry(ptr, i);
	}
	if (rc_unlock() == 0) {
		ring_count = 0;
		rc_lock();
	}
	occupied_mask = 0;

	ring_lock();
}
