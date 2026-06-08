/*
 * Deferred-free queue for temporal overlap of syscall allocations.
 *
 * Sanitise callbacks allocate structs/buffers that post callbacks would
 * normally free immediately after the syscall returns.  This means the
 * kernel only ever sees one allocation at a time — no temporal overlap.
 *
 * By queueing allocations for delayed free (5-50 more syscalls), we
 * keep multiple allocations alive simultaneously, increasing the chance
 * of hitting UAF, stale-reference, and double-free bugs in the kernel.
 *
 * The queue is a flat array scanned linearly.  At 64 entries and
 * ~10 bytes per entry, this is fast enough — children do millions of
 * syscalls, so the tick overhead is negligible.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/mman.h>
#include <unistd.h>

#include "child.h"
#include "deferred-free.h"
#include "pc_format.h"
#include "random.h"
#include "shm.h"
#include "stats_ring.h"
#include "trinity.h"
#include "utils.h"

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
 * Run the actual TTL-decrement-and-free loop on 1-in-N tick calls.
 * The other (N-1) calls bail before taking the mprotect bracket.
 * N must be a power of two so the modulo collapses to a bitmask.
 *
 * Side effect: TTL is effectively multiplied by N.  Nominal range
 * 5-50 syscalls becomes 80-800 syscalls of in-ring lifetime.  This
 * is fine -- and arguably better for catching UAF overlap -- but
 * worth knowing when reading the TTL constants above.
 *
 * 8 was insufficient for the head->array container lifetime in
 * add_object's OBJ_LOCAL grow path: a get_random_object() reader
 * interrupted by a signal whose handler runs syscalls (ticking the
 * ring) while the original code holds head->array in a register/
 * cache can outlive a 40-400 syscall TTL when the signal handler
 * is heavy.  16 keeps the same shape but lifts the headroom to a
 * range no plausible reader window touches.
 */
#define DEFERRED_TICK_BATCH	16

struct deferred_entry {
	void *ptr;
	unsigned int ttl;
};

/*
 * Side-set of "live" malloc results, opt-in.  Allocation sites that
 * know their pointer is bound to flow through deferred_free_enqueue
 * (post_state sanitisers, alloc_object, ARG_STRUCT_PTR_IN/OUT, execve
 * argv/envp fabrication, the mostly-deferred-freed bpf/setsockopt/
 * getsockopt/seccomp slots) allocate via zmalloc_tracked(), which
 * calls deferred_alloc_track() on the returned pointer; plain
 * zmalloc() leaves the result out of the side-set.
 * deferred_free_enqueue() consumes the matching entry to confirm the
 * pointer it has been handed is a real malloc result before letting
 * it through to free().
 *
 * The pre-existing looks_like_corrupted_ptr() heuristic only rejects
 * sub-page / above-canonical / mis-aligned values.  A wholesale stomp
 * that scribbles rec->post_state (or rec->aN) with an address that
 * happens to land inside the heap arena passes every band of that test
 * -- 8-byte aligned, in user VA, not pid-shaped -- yet is not a real
 * malloc-return.  Eight ASAN "bad-free" reports hit exactly that gap:
 * the freed pointer was heap-region but not at an allocation start, so
 * libc's free() rejects it.  Tracking the set of live malloc results
 * for the opt-in subset gives us ground truth the pointer-shape
 * heuristic can't, for the pointers that actually flow through this
 * gate.
 *
 * Opt-in (rather than every __zmalloc result) keeps the ring's input
 * population aligned with its consumer.  Sites whose pointer is
 * released via direct free() (process-lifetime tables, per-child obj/
 * fd/hash arrays, error-path fallbacks) used to leave a stale entry
 * behind after each release; with opt-in they never enter the ring,
 * so the previous failure mode -- a fuzzed scribble matching a stale
 * entry and tricking alloc_track_consume() into approving a wrong-
 * free -- disappears.  The mirror-image failure (forgetting to opt in
 * at a site that should have) reduces to a deferred_free_reject
 * leak, observable in stats; that is the safer direction to err.
 *
 * Sized for the in-flight window: between a sanitise's zmalloc and the
 * matching post handler's deferred_free_enqueue, the same syscall does
 * a handful of additional zmallocs (snap struct, arg generators, etc.)
 * -- well under a hundred in the worst case.  256 entries gives ample
 * headroom; on overflow we evict in arrival order, which only causes a
 * benign drop (memory leak) of the evicted pointer's eventual free.
 * Narrowing the input set to the opt-in subset buys back ring head-
 * room that init-time / per-child-table zmallocs used to consume.
 *
 * Process-local: zero-initialised BSS, COW-shared at fork, written
 * single-threaded by the owning child.  No locking needed.
 */
/* Bumped 256 -> 4096 on 2026-05-29 after observing
 * maps_reject_alloc_track_miss at 354K/s (1.90x pool_empty) in fuzz.
 * Long-lived MMAP_ANON pool entries were rotating out from under
 * mm/maps.c:103's alloc_track_lookup gate before child cycles
 * completed, making get_map_handle false-reject legitimate slots and
 * burn retry budget.  4096 leaves headroom for pool entries plus
 * recent zmalloc_tracked churn without rotating live entries out. */
#define ALLOC_TRACK_SIZE	4096

static void *alloc_track[ALLOC_TRACK_SIZE];
static unsigned int alloc_track_head;

/*
 * Side-set membership accelerator for alloc_track[].
 *
 * alloc_track_consume() and alloc_track_lookup() previously did an
 * O(N) backward scan over alloc_track[] for every call.  Hit cost was
 * cheap (post handlers free a few syscalls after the matching
 * __zmalloc, so the hit lives near head), but miss cost was always
 * the full 256-slot walk -- and misses are the path that fires when
 * a scribbled snapshot field arrives at deferred_free_enqueue, which
 * is exactly the case where we want a fast reject, not a slow one.
 *
 * alloc_track[] remains the source of truth for lifecycle (which slot
 * a ptr lives in, who got displaced on rotation); the hash mirrors it
 * for membership only.  Every write to alloc_track[] in this file is
 * paired with the matching hash op inside the same function, so the
 * two stay in lock-step.  A divergence here isn't just a perf miss --
 * it would be a correctness bug in the deferred-free gate, the very
 * thing the opt-in zmalloc_tracked() set was built around.
 *
 * 16384 slots vs ALLOC_TRACK_SIZE=4096 -> 0.25 max load factor, keeping
 * the average probe length ~1.3 even at full occupancy.  Power of two
 * so the modulo collapses to a bitmask.  BSS-resident (no mprotect
 * bracket, not inside the mmap'd ring): the ring is mmap'd-shared
 * because shared_regions[] only protects mmap'd VAs from fuzzed-write
 * stomps, but the hash has no pointer values an attacker could turn
 * into a free() target -- the worst a stomp here can do is induce
 * the same false-negative we already tolerate in the duplicate edge
 * case below.
 *
 * Fibonacci hashing: ptr>>4 strips the 4 always-zero low bits glibc
 * malloc gives us on x86_64 (16-byte-aligned chunks on 64-bit), then
 * multiplies by the golden-ratio constant.  Top 10 bits of the
 * product become the slot index, which scatters pointer streams that
 * share a common prefix (e.g. addresses drawn from the same arena)
 * across the table.
 *
 * Duplicate-ptr edge case: if the same address enters alloc_track[]
 * twice (rare; requires a direct free() outside the deferred path
 * before a re-malloc returns the same address), the hash records one
 * membership entry.  When the first array slot rotates out, the
 * displaced ptr is hash_remove()d -- the second slot's copy is
 * orphaned (hash says no, array says yes), and a subsequent
 * deferred_free_enqueue of that ptr is falsely rejected.  That is a
 * deferred_free_reject leak, not a bad-free; per the opt-in vs.
 * implicit-track design rationale further up, the safer direction
 * to err.
 */
#define ALLOC_TRACK_HASH_SHIFT	14
#define ALLOC_TRACK_HASH_SIZE	(1U << ALLOC_TRACK_HASH_SHIFT)
#define ALLOC_TRACK_HASH_MASK	(ALLOC_TRACK_HASH_SIZE - 1U)

/* 2^64 / phi, rounded to nearest odd: the 64-bit Fibonacci constant. */
#define ALLOC_TRACK_FIB_MUL	0x9E3779B97F4A7C15ULL

static void *alloc_track_hash[ALLOC_TRACK_HASH_SIZE];

static inline unsigned int alloc_track_hash_index(void *ptr)
{
	uint64_t key = (uint64_t)(uintptr_t)ptr >> 4;

	return (unsigned int)((key * ALLOC_TRACK_FIB_MUL) >>
			      (64 - ALLOC_TRACK_HASH_SHIFT));
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
 * In-flight pointer set: mirrors "currently admitted to the deferred
 * ring" membership.  Separate from alloc_track_hash[] (which tracks
 * the broader "deferred-free-eligible alloc side-set" populated by
 * zmalloc_tracked() and drained by alloc_track_consume), so the two
 * lifecycles don't conflict.
 *
 * Populated at the tail of deferred_free_enqueue after the ring slot
 * write succeeds; cleared at the tail of free_ring_entry on the
 * successful free() path.  Read by the in-flight-miss gate in
 * free_ring_entry to reject ring slots whose pointer was scribbled by
 * a sibling fuzzed value-result syscall between admission and TTL
 * expiry -- the scribbled value was never admitted, so the lookup
 * misses and the slot is dropped instead of being fed to free().
 *
 * Storage shape mirrors alloc_track_hash[] (1024 slots, Fibonacci
 * index, open-addressed with shift-back deletion).  Sized for the
 * 64-slot ring plus headroom for stomp orphans accumulated between
 * GC sweeps; an idle slot costs 8 bytes of BSS.
 *
 * Storage lives in BSS (zero-init, COW-shared at fork, written
 * single-threaded by the owning child) -- NOT mprotect-armored
 * against an in-ring stomp targeting the set's own pages.  A stomp
 * that landed on inflight_hash[] could flip a membership bit and
 * either let a bad free through (set says "present" when ptr was
 * never admitted) or reject a clean free (set says "absent" when ptr
 * is live).  The residual gap motivates a planned follow-up that
 * moves the membership store into an mprotect-bracketed mmap'd
 * region, the same shape ring[] already uses.
 */
#define INFLIGHT_HASH_SHIFT	10
#define INFLIGHT_HASH_SIZE	(1U << INFLIGHT_HASH_SHIFT)
#define INFLIGHT_HASH_MASK	(INFLIGHT_HASH_SIZE - 1U)

static void *inflight_hash[INFLIGHT_HASH_SIZE];

static inline unsigned int inflight_hash_index(void *ptr)
{
	uint64_t key = (uint64_t)(uintptr_t)ptr >> 4;

	return (unsigned int)((key * ALLOC_TRACK_FIB_MUL) >>
			      (64 - INFLIGHT_HASH_SHIFT));
}

static void inflight_hash_insert(void *ptr)
{
	unsigned int idx = inflight_hash_index(ptr);
	unsigned int probes;

	for (probes = 0; probes < INFLIGHT_HASH_SIZE; probes++) {
		if (inflight_hash[idx] == NULL) {
			inflight_hash[idx] = ptr;
			return;
		}
		if (inflight_hash[idx] == ptr)
			return;
		idx = (idx + 1) & INFLIGHT_HASH_MASK;
	}
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

	hole = idx;
	for (probes = 0; probes < INFLIGHT_HASH_SIZE; probes++) {
		unsigned int natural;
		unsigned int dist_to_hole;
		unsigned int dist_to_natural;

		idx = (idx + 1) & INFLIGHT_HASH_MASK;
		if (inflight_hash[idx] == NULL) {
			inflight_hash[hole] = NULL;
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
}

static bool inflight_hash_contains(void *ptr)
{
	unsigned int idx = inflight_hash_index(ptr);
	unsigned int probes;

	for (probes = 0; probes < INFLIGHT_HASH_SIZE; probes++) {
		if (inflight_hash[idx] == NULL)
			return false;
		if (inflight_hash[idx] == ptr)
			return true;
		idx = (idx + 1) & INFLIGHT_HASH_MASK;
	}
	return false;
}

void deferred_alloc_track(void *ptr)
{
	unsigned int slot;
	void *displaced;

	if (ptr == NULL)
		return;

	slot = alloc_track_head % ALLOC_TRACK_SIZE;
	displaced = alloc_track[slot];

	alloc_track[slot] = ptr;
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
}

/*
 * Consume the entry matching @ptr.  Returns true if found (and clears
 * the slot); false if the pointer was not in the side-set, meaning the
 * caller is about to free something __zmalloc() never produced.
 *
 * Hash-gated fast reject: misses short-circuit without touching the
 * 256-slot array.  This is the path that fires when a fuzzed scribble
 * arrives at deferred_free_enqueue (heap-shape, not malloc-returned),
 * and prior to the hash it was always a full 256-slot backward walk.
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
			alloc_track[idx] = NULL;
			alloc_track_hash_remove(ptr);
			return true;
		}
		idx = (idx - 1) & (ALLOC_TRACK_SIZE - 1);
	}
	return false;
}

/*
 * Refresh an existing tracked entry's LRU position without freeing it.
 * If @ptr is in the ring, null its current slot + remove from hash, then
 * re-insert at head.  If @ptr is not present (already rotated out), just
 * insert at head.  Either way the post-call state has @ptr exactly once
 * in the ring (at head) and exactly once in the hash.
 *
 * Pair with the OBJ_LOCAL anon-pool dedup-skip in clone_global_mmap_pool:
 * dedup'd pool entries don't trigger a fresh __zmalloc_tracked, so without
 * this refresh their alloc_track slots rotate out under churn from
 * unrelated tracked allocations.  Wave-F's 256->4096 widen was outpaced
 * 100x at full throughput (bisect 2026-05-30 localized to f531bb72cd9e).
 */
void alloc_track_refresh(void *ptr)
{
	if (ptr == NULL)
		return;
	(void)alloc_track_consume(ptr);
	deferred_alloc_track(ptr);
}

/*
 * Synchronously free a zmalloc_tracked() pointer.  alloc_track_consume()
 * pulls the entry out of both alloc_track[] and alloc_track_hash[] in
 * one shot (hash-gated reject, then backward array scan with paired
 * hash_remove on the hit), which is exactly the removal the deferred
 * ring would have done at TTL expiry — but here without the queue
 * latency.  The consume-miss case (pointer was never tracked, was
 * already consumed, or rotated out) is silently tolerated: free()ing
 * a non-tracked pointer is not by itself a bug, and a hard error here
 * would punish callers that legitimately mix tracked and untracked
 * allocations on the same release path.
 *
 * inflight_hash_remove() keeps the in-flight set symmetric: if this
 * buffer was already admitted to the deferred-free ring by another
 * owner, drop the stale positive so a later ring eviction of that
 * slot sees the entry gone and skips it instead of double-freeing.
 * The remove no-ops on a miss, so the common case (ptr was never
 * enqueued) costs only one hash probe.
 */
void tracked_free_now(void *ptr)
{
	if (ptr == NULL)
		return;

	alloc_track_consume(ptr);
	inflight_hash_remove(ptr);
	free(ptr);
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

/*
 * Ring storage lives in an mmap'd region whose address range is registered
 * with shared_regions[] via track_shared_region().  That tracking lets
 * avoid_shared_buffer() and the mm-syscall sanitisers refuse fuzzed
 * pointers/lengths that would land inside the ring -- previously the array
 * lived in trinity's BSS, which is NOT registered with shared_regions[],
 * so a fuzzed write could scribble ring[i].ptr with a pid-shaped value
 * (residual-cores triage matched si_addr=0x378a02 against the killing
 * process's pid) and the next deferred_free_tick() would free() the bogus
 * pointer.
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
static struct deferred_entry *ring;
static unsigned int ring_count;
static size_t ring_bytes;

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
 * Bracket every writer/reader of ring[] with mprotect().  Between
 * ticks the ring sits at PROT_NONE; any fuzzed value-result syscall
 * that tries to scribble inside it now SIGSEGVs in the kernel's
 * copy_from_user instead of silently overwriting ring[i].ptr with a
 * pid-shaped value (the cluster-1 root cause: ~200 SIGSEGVs at
 * deferred_free_tick+0x49 with si_addr ~= si_pid).  mprotect is
 * async-signal-safe so these are safe to call from anywhere
 * deferred_free_* is reachable.
 *
 * ring_unlock() returns RING_UNLOCK_OK on success, RING_UNLOCK_ENOMEM
 * when the kernel rejected the protection change for VMA-budget
 * reasons (per-process /proc/sys/vm/max_map_count cap approached, or
 * splitting the surrounding mapping would overshoot it), and
 * RING_UNLOCK_FAIL on any other failure.  Callers handle the three
 * cases differently: ENOMEM flips the per-child drain-aggressive
 * latch so the next tick drains the queue regardless of TTL (the
 * sooner the ring empties, the sooner the held-back glibc-arena
 * chunks can be returned to the kernel and the VMA budget recovers);
 * generic FAIL just falls back to immediate free for this ptr;
 * either way the caller bails before touching ring[].  Pre-trio the
 * function returned bool, fold both fail cases into one path, and the
 * VMA-exhaustion class observed in the 22:38 run (113/362 bug-logs,
 * 7424 "mprotect RW failed" lines) survived as a silent leak of
 * queued ptrs while the original bracket landed it logged-and-
 * returned, leaving the page at PROT_NONE while the caller fell
 * through -- ~311 self-inflicted SEGV_ACCERR crashes per 1.5h fuzz
 * run, split across deferred_free_tick+0x7e (the ring[i].ttl read in
 * the loop body) and deferred_free_enqueue+0x89 (the ring[i].ptr ==
 * NULL slot scan).  The current routing keeps the page PROT_NONE
 * (no caller proceeds on failure) but stops adding queue pressure
 * while the kernel is at the VMA limit.
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
 * Tear down the ring after ring_unlock() returned ENOMEM.  The page is
 * still PROT_NONE at this point (the RW flip is exactly what failed);
 * if we just bail and leave it that way, every sibling fuzzed value-
 * result syscall whose buffer lands inside the ring SEGV_ACCERRs in
 * copy_to_user, and every subsequent ring_unlock retry hits the same
 * ENOMEM and emits another "mprotect RW failed: errno=12" line.  RC's
 * 02:36 triage caught this as a SEGV_ACCERR storm of 2282 faults across
 * 2270 children at recurring redzone pages, with the matching log
 * volume saturating bug-logs (8k-25k mprotect-RW-failed lines per run).
 *
 * Releasing the VMA slot with munmap() drops both failure modes at the
 * source: the PROT_NONE residue is gone (so no more SEGV_ACCERR fault-
 * bait), and the kernel gets the VMA back to satisfy whatever split the
 * wider mm-syscall workload needed.  Cost: every ptr currently in the
 * ring is leaked from glibc's tracking until the child exits.  That is
 * the same tradeoff d8943d44's drain-aggressive bypass already accepted
 * for the per-allocation UAF-detection window -- abandoning the
 * remaining ring slots is the worst case of that bypass, taken once
 * when the kernel has actually told us it cannot satisfy more mprotect
 * splits.
 *
 * Untrack the shared region BEFORE munmap so range_overlaps_shared()
 * stops answering yes on a VA the kernel will reclaim out from under
 * it -- the pairing rule the check-static script enforces for every
 * other track/munmap site.  inflight_hash[] is cleared in lock-step
 * with ring_count so the orphan-sweep at next tick (which won't run,
 * since ring_count is now zero) doesn't have a stale picture to recover
 * from if a future commit re-arms the ring; the heap chunks the hash
 * entries pointed at are leaked alongside the queued ptrs themselves.
 *
 * Idempotent: a second caller (e.g. a flush after the enqueue path
 * already disposed) sees ring==NULL and returns.  After dispose every
 * deferred_free_* entry point falls through to the no-op path --
 * enqueue's ring==NULL gate routes to immediate free(), tick/flush bail
 * on ring_count==0 -- so the deferred-free machinery is functionally
 * off in this child for the rest of its life.  Per-child by fork's COW,
 * so a flap in one child doesn't perturb siblings.
 */
static void ring_dispose_after_enomem(void)
{
	if (ring == NULL)
		return;

	untrack_shared_region((unsigned long)ring, ring_bytes);
	if (munmap(ring, ring_bytes) != 0)
		outputerr("deferred_free: munmap ring after ENOMEM failed: errno=%d\n",
			  errno);

	ring = NULL;
	ring_count = 0;
	occupied_mask = 0;
	memset(inflight_hash, 0, sizeof(inflight_hash));
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
	unsigned long cur = __atomic_load_n(&shm->stats.deferred_free_outstanding_vmas,
					    __ATOMIC_RELAXED);

	while (v > cur) {
		if (__atomic_compare_exchange_n(
				&shm->stats.deferred_free_outstanding_vmas,
				&cur, (unsigned long)v, false,
				__ATOMIC_RELAXED, __ATOMIC_RELAXED))
			return;
	}
}

void deferred_free_init(void)
{
	const size_t raw = sizeof(struct deferred_entry) * DEFERRED_RING_SIZE;

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
	__atomic_add_fetch(&shm->stats.deferred_free_reject_misaligned, 1, __ATOMIC_RELAXED);
	return true;
}

/*
 * Reject pid-scribbled / canonical-out-of-range / misaligned values
 * BEFORE they ever reach the ring.  Cluster-1/2/3 root cause
 * (residual-cores triage 2026-05-02): a sibling fuzzed value-result
 * syscall scribbles a tid/pid into rec->aN, the post handler does
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
	__atomic_add_fetch(&shm->stats.deferred_free_reject_corrupt_shape, 1, __ATOMIC_RELAXED);
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
	__atomic_add_fetch(&shm->stats.deferred_free_reject_non_heap, 1, __ATOMIC_RELAXED);
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
	 * The enqueue path validates ptr against the heap-
	 * bounds and shared-region bands BEFORE ring_unlock().
	 * Once unlocked, the slot sits RW until ring_lock()
	 * runs, so an in-flight stomp from a sibling fuzzed
	 * value-result syscall can scribble ring[oldest].ptr
	 * between when the slot was last validated and when
	 * the full-ring eviction here decides to free it.
	 * Re-run the surviving stateless guards plus the in-
	 * flight set membership check before free()ing so a
	 * wild pointer becomes a telemetry bump instead of a
	 * crash.  alloc_track_consume() already fired at
	 * enqueue and would always miss here -- skipped, not
	 * re-run.  Counter only (no per-rejection log): the
	 * eviction case is rarer than the enqueue rejection
	 * paths, whose 1-in-1000 caller-PC logs already prove
	 * the stomp pattern.
	 *
	 * The inflight_hash_contains() check is the strongest
	 * signal here: if evict_ptr was admitted by this child,
	 * it is in the set; if a stomp swapped the slot to some
	 * other value, the set does not know that value and the
	 * lookup misses.  Heap/shared-region guards remain as
	 * belt-and-suspenders for the case where the in-flight
	 * set itself is scribbled (BSS, no mprotect armor yet).
	 */
	if (!is_in_glibc_heap(evict_ptr) ||
	    range_overlaps_shared((unsigned long)evict_ptr, 1) ||
	    !inflight_hash_contains(evict_ptr))
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
		free(evict_ptr);
	}
	ring[oldest].ptr = NULL;
	occupied_mask &= ~(1ULL << oldest);
	ring_count--;
}

/*
 * Shared implementation for deferred_free_enqueue() and
 * deferred_free_enqueue_or_leak().  The full reject / admit pipeline
 * is identical for the two entry points; only the five
 * under-pressure fallback paths branch on @leak_on_pressure.  On a
 * leak path the caller's contract is "the buffer survives until
 * child exit"; the heap chunk is not free()d, the alloc-track slot
 * has already been drained by alloc_track_consume() so no stale
 * mirror entry is left behind, and the kernel reclaims the address
 * space when the child exits.
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
	 */
	if (!alloc_track_consume(ptr)) {
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
		__atomic_add_fetch(&shm->stats.deferred_free_reject_untracked, 1, __ATOMIC_RELAXED);
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
		__atomic_add_fetch(&shm->stats.deferred_free_reject_shared_region, 1, __ATOMIC_RELAXED);
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
	 * Placed AFTER alloc_track_consume so the tracking-set entry is
	 * already drained (otherwise routing around the ring would leave
	 * a stale alloc_track[] slot trickling out via LRU rotation);
	 * placed BEFORE ring_unlock so the rejected enqueue does not pay
	 * the mprotect bracket cost.
	 */
	if (ring_count > g_max_vmas / 2) {
		__atomic_add_fetch(&shm->stats.deferred_free_vma_fallback_immediate,
				   1, __ATOMIC_RELAXED);
		if (leak_on_pressure)
			__atomic_add_fetch(&shm->stats.deferred_free_pre_dispatch_leaked,
					   1, __ATOMIC_RELAXED);
		else
			free(ptr);
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
		if (leak_on_pressure)
			__atomic_add_fetch(&shm->stats.deferred_free_pre_dispatch_leaked,
					   1, __ATOMIC_RELAXED);
		else
			free(ptr);
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
	 * Pre-dispose this path set a sticky drain-aggressive latch and
	 * let the next tick chew through the ring; that left every queued
	 * ptr's PROT_NONE page persistent in the meantime, which is
	 * exactly the residue RC's 02:36 SEGV_ACCERR storm rode in on.
	 * Dispose drops the page outright, so the latch infrastructure is
	 * gone (no consumer left to set it to true).
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
			__atomic_add_fetch(&shm->stats.deferred_free_enomem_drain,
					   1, __ATOMIC_RELAXED);
			ring_dispose_after_enomem();
			if (leak_on_pressure)
				__atomic_add_fetch(&shm->stats.deferred_free_pre_dispatch_leaked,
						   1, __ATOMIC_RELAXED);
			else
				free(ptr);
			return;
		}
		if (r != RING_UNLOCK_OK) {
			if (leak_on_pressure)
				__atomic_add_fetch(&shm->stats.deferred_free_pre_dispatch_leaked,
						   1, __ATOMIC_RELAXED);
			else
				free(ptr);
			return;
		}
	}

	if (ring_count == DEFERRED_RING_SIZE)
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
		if (leak_on_pressure)
			__atomic_add_fetch(&shm->stats.deferred_free_pre_dispatch_leaked,
					   1, __ATOMIC_RELAXED);
		else
			free(ptr);
		return;
	}

	/* Find an empty slot.  After the full-ring eviction above, at
	 * least one bit in occupied_mask is clear, so ~occupied_mask is
	 * non-zero and __builtin_ctzll's UB-on-zero case can't fire. */
	i = __builtin_ctzll(~occupied_mask);
	ring[i].ptr = ptr;
	ring[i].ttl = RAND_RANGE(DEFERRED_TTL_MIN, DEFERRED_TTL_MAX);
	occupied_mask |= 1ULL << i;
	ring_count++;
	deferred_free_record_outstanding(ring_count);

	ring_lock();

	/*
	 * Record this admission in the in-flight set so the drain-time
	 * gate can tell an unscrobbed slot from a scribbled one.  Outside
	 * the ring_unlock bracket because the set is BSS-resident -- no
	 * mprotect cost on this write.
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
 * sanity bands.  Both the tick (TTL expiry) and flush (child exit)
 * paths route through here -- pre-helper, only tick had these checks,
 * so a corrupted ring entry surviving until child exit would silently
 * free a bogus pointer through deferred_free_flush().  The tick guard
 * rejected ~47.7k corrupt-pointer scribbles in a single 6.76h run
 * (~2/sec), so the ring DOES get scribbled in practice; every entry
 * the tick guard would have rejected was being silently freed by
 * flush instead.
 *
 * Caller must clear ring[slot].ptr (and decrement ring_count where
 * it tracks per-slot) before calling.  Clearing first means a signal
 * that longjmps out of fn() can't leave a freed pointer pending in
 * the ring.
 *
 * Re-run the same stateless gates deferred_free_enqueue used to admit
 * the pointer in the first place: shape (pid-scribbled / sub-page /
 * non-canonical / misaligned), heap-bounds, shared-region overlap.
 * Today's ASAN run logged 105 "attempting free on un-malloc'd"
 * crashes whose root cause is the ring entry being scribbled between
 * the enqueue admission check and TTL expiry -- the slot lives RW
 * inside ring_unlock() brackets, but a sibling fuzzed value-result
 * syscall can still land a stomp into the same page during that
 * window.  Before this guard, free_ring_entry checked only sub-page
 * and alignment; every stomp that landed on something heap-shaped
 * but not actually malloc-returned was being fed straight to free().
 *
 * In-flight set membership is the fourth (and definitive) gate.  A
 * stomp value whose shape passes heap-bounds and avoids the shared
 * regions can still mismatch the originally admitted pointer -- the
 * inflight_hash records what enqueue admitted, so a scribble flips
 * the lookup from hit to miss whether the new value looks plausible
 * or not.  Ordered last so the stateless gates can attach a more
 * specific reason string when they happen to fire; in-flight-miss
 * fires when nothing else matches but the value isn't one we ever
 * admitted, which is the "stomped to a coincidentally heap-shaped
 * value" case the earlier 3 gates by design cannot catch.
 *
 * alloc_track_consume already fired at enqueue and would always miss
 * here -- skipped, not re-run.  The remaining gates are stateless and
 * cheap enough to re-evaluate per drain.
 *
 * Bumps STATS_FIELD_DEFERRED_FREE_CORRUPT_PTR (or its parent
 * fallback) on any rejection, matching the existing pattern; the
 * specific gate that fired shows up in the outputerr log line.
 *
 * On the clean-free path the entry is removed from inflight_hash so
 * the GC sweep does not later mistake it for an orphan.
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
	else if (!inflight_hash_contains(ptr))
		reason = "in-flight-miss";

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
	free(ptr);
}

/*
 * Periodic garbage collection of orphaned in-flight entries.
 *
 * In-ring stomps can swap a ring slot's ptr to some other value before
 * the drain fires.  When the drain reaches that slot, free_ring_entry's
 * in-flight-miss gate sees the stomped value (not the originally
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
	 * Leaving the ring at PROT_NONE here was RC's dominant 02:36
	 * SEGV_ACCERR storm signature -- the page persists as fault-bait
	 * for sibling fuzzed value-result syscalls, and the next tick
	 * hits the same ENOMEM and emits another "mprotect RW failed"
	 * line (8k-25k per run in RC's three-build trend, dominant
	 * bug-log volume).  Dispose the ring outright so the PROT_NONE
	 * residue goes away; the entries currently queued are leaked
	 * (lost forever from glibc's tracking until the child exits),
	 * which is the worst case of d8943d44's drain-aggressive
	 * tradeoff -- acceptable because the alternative is the loop
	 * above continuing to thrash for the rest of the run.
	 *
	 * RING_UNLOCK_FAIL (any other errno) keeps the prior behaviour:
	 * bail this tick, leave the page PROT_NONE, and retry on the
	 * next tick.  A transient EACCES from a not-yet-sanitised mm-
	 * syscall is not the VMA-budget class and does not warrant
	 * abandoning the ring.
	 */
	r = ring_unlock();
	if (r == RING_UNLOCK_ENOMEM) {
		__atomic_add_fetch(&shm->stats.deferred_free_rw_restore_enomem,
				   1, __ATOMIC_RELAXED);
		ring_dispose_after_enomem();
		return;
	}
	if (r != RING_UNLOCK_OK)
		return;

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
		__atomic_add_fetch(&shm->stats.deferred_free_rw_restore_enomem,
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
	ring_count = 0;
	occupied_mask = 0;

	ring_lock();
}
