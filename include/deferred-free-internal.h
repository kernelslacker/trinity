#pragma once

/*
 * Constants and cross-file declarations of the deferred-free queue, shared
 * by persist/deferred-free*.c and, for the sizing constants, with
 * tests/deferred_free_test.c so its arithmetic follows the production
 * values.  Not part of the public API in deferred-free.h.
 *
 * Include it after every other project header: the ring accessor macros at
 * the end would rewrite a parameter named ring in any prototype declared
 * after them.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DEFERRED_RING_SIZE	64

/*
 * Decrement-and-free runs 1-in-N ticks (N power-of-two -> bitmask);
 * the other N-1 bail before the mprotect bracket.  Effective TTL is
 * thus ~N x the 5-50 nominal (80-800 syscalls) -- intentional
 * headroom for UAF overlap.
 */
#define DEFERRED_TICK_BATCH	16

/* 4096 slots.  Long-lived MMAP_ANON pool entries must stay tracked
 * until their child cycle completes, or get_map_handle's
 * alloc_track_lookup gate false-rejects legitimate slots and burns
 * retry budget.  4096 holds those pool entries plus recent
 * zmalloc_tracked churn without rotating live entries out from under
 * the lookup. */
#define ALLOC_TRACK_SIZE	4096

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

struct deferred_entry {
	void *ptr;
	unsigned int ttl;
};

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
 * Ring control state -- the ring pointer, its mmap'd size, the
 * in-flight slot count, and the per-slot occupancy bitmap.  All four
 * live in their own small mmap'd armor page so a sibling fuzzed
 * value-result syscall cannot scribble the values that DRIVE ring[]'s
 * own mprotect/munmap bracket: a stomped ring would point mprotect at
 * an arbitrary VA, a stomped ring_bytes would extend munmap into
 * unrelated VMAs, a stomped ring_count would mis-gate the enqueue
 * full-ring check and the tick early-bail, and a stomped
 * occupied_mask would either (mask=0 while ring is really full)
 * bypass the full-ring eviction and orphan a live slot on the next
 * enqueue, or (mask=~0ULL while ring is really empty) drive
 * __builtin_ctzll(~mask) into its UB-on-zero case.  ring and
 * ring_bytes are write-once during init (plus the dispose-time
 * NULL/zero clear); ring_count and occupied_mask mutate per enqueue
 * and drain.  Steady state of the armor page is PROT_READ so the
 * dominant reads (the "if (ring == NULL)" / "if (ring_count == 0)"
 * fast-bail checks, the ring_count comparison in the full-ring
 * branch, and __builtin_ctzll(~occupied_mask) in the slot-hunt)
 * execute without a syscall; the few writer paths flip RW via
 * rc_unlock()/rc_lock() for the duration of the mutation.  The field
 * access pattern is hidden behind the file-scope macros below so the
 * rest of the file keeps reading like ring/ring_count/ring_bytes/
 * occupied_mask were still plain file-static scalars.
 */
struct ring_control {
	struct deferred_entry *ring;
	size_t ring_bytes;
	unsigned int ring_count;
	uint64_t occupied_mask;
};

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

#define GEN_ARENA_SLOTS			8
#define GEN_ARENA_ENTRIES		256

enum gen_arena_state {
	GEN_EMPTY = 0,
	GEN_ACTIVE,
	GEN_SEALED,
};

struct gen_arena {
	void *ptrs[GEN_ARENA_ENTRIES];
	unsigned int count;
	unsigned long armed_tick;	/* tick_counter when it went ACTIVE */
	unsigned long sealed_tick;	/* tick_counter when it went SEALED */
	enum gen_arena_state state;
};

struct gen_arena_region {
	struct gen_arena arenas[GEN_ARENA_SLOTS];
	unsigned int active_idx;
	unsigned long tick_counter;	/* monotonic batched-tick clock */
};

/*
 * The free paths that go through tracked_free_checked(), so a consume miss
 * is charged to the counter of the path that made it.
 */
enum tracked_free_site {
	TRACKED_FREE_SITE_RING_EVICT,	/* ring_evict_oldest_safe */
	TRACKED_FREE_SITE_RING_DRAIN,	/* free_ring_entry */
	TRACKED_FREE_SITE_IMMEDIATE,	/* tracked_free_now + enqueue immediate-free fallbacks */
	TRACKED_FREE_SITE_GEN_RETIRE,	/* gen_arena_retire_one -- generation-arena drain */
};

/*
 * Defined in deferred-free-regions.c, which maps the mprotect-armoured
 * regions (alloc_track's backing, ring_control, the ring, the generation
 * arena) and brackets every mutation of them: *_unlock() opens the RW
 * window for one mutation and *_lock() restores the steady state (PROT_READ,
 * PROT_NONE for the ring), or leaves that to deferred_free_seal_all() when
 * batching.
 */
extern struct ring_control *rc;
extern struct gen_arena_region *gen;

int alloc_track_unlock(void);
void alloc_track_lock(void);
int rc_unlock(void);
void rc_lock(void);
enum ring_unlock_result ring_unlock(void);
void ring_lock(void);
int gen_unlock(void);
void gen_lock(void);

/* Tear the ring down after ring_unlock() reports ENOMEM. */
void ring_dispose_after_enomem(void);

/*
 * alloc_track storage, defined in deferred-free-alloc-track.c.
 * deferred_free_init() maps the backing region and points these into it.
 */
extern void **alloc_track;
extern void **alloc_track_hash;
extern size_t *alloc_track_sizes;

/*
 * Remove @ptr from the side-set; true iff it was live.  tracked_free_checked()
 * frees only when that succeeds and otherwise charges the miss to @site.
 */
bool alloc_track_consume(void *ptr);
bool tracked_free_checked(void *ptr, enum tracked_free_site site);

/* Reads vm.max_map_count once, in the parent, for the enqueue VMA cap. */
void deferred_free_read_max_map_count(void);

/*
 * Accessors for the ring_control fields, so code reads as if ring and its
 * bookkeeping were plain file-static scalars.  Last in this header: the
 * macros follow every declaration they could rewrite.
 */
#define ring		(rc->ring)
#define ring_bytes	(rc->ring_bytes)
#define ring_count	(rc->ring_count)
#define occupied_mask	(rc->occupied_mask)

/*
 * occupied_mask: one bit per ring slot (1 == occupied, 0 == free).
 * Lets enqueue find the next empty slot in O(1) via
 * __builtin_ctzll(~occupied_mask) instead of a linear scan over all
 * 64 entries.  Maintained alongside ring_count: every ptr write that
 * fills a slot sets the bit, every clear that empties a slot clears
 * it.  Lives in the ring_control armor page (see struct definition
 * above) -- reads at rest hit PROT_READ without a syscall; writers
 * update it inside the same rc_unlock/rc_lock bracket that guards
 * ring_count.  uint64_t suffices because DEFERRED_RING_SIZE == 64.
 */
