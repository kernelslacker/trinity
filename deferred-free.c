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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/mman.h>

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
#define ALLOC_TRACK_SIZE	256

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
 * 1024 slots vs ALLOC_TRACK_SIZE=256 -> 0.25 max load factor, keeping
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
#define ALLOC_TRACK_HASH_SHIFT	10
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
 * occupancy is capped at ALLOC_TRACK_SIZE (256) << table size, so a
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

static bool alloc_track_hash_contains(void *ptr)
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

	if (!alloc_track_hash_contains(ptr))
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
 * Non-consuming peer of alloc_track_consume: returns true if @ptr is
 * present in the side-set without removing it.  Used by readers that
 * want to validate a stored pointer (e.g. an object-pool slot) before
 * the first deref, but must not perturb the consume-on-free invariant
 * the deferred_free_enqueue path relies on.
 */
bool alloc_track_lookup(void *ptr)
{
	return alloc_track_hash_contains(ptr);
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
 * ring_unlock() returns false on mprotect failure so callers bail out
 * before touching ring[].  Failure is rare but does happen under
 * fuzzing pressure (kernel VMA-limit ENOMEM when the per-process
 * map_count cap is approached, transient EAGAIN under memory pressure,
 * or a not-yet-sanitised mm-syscall slipping past the shared-region
 * filter and modifying the ring's VMA).  When the original bracket
 * landed it logged-and-returned, leaving the page at PROT_NONE while
 * the caller fell through into the ring access loop -- ~311 self-
 * inflicted SEGV_ACCERR crashes per 1.5h fuzz run with si_addr
 * matching the ring page, split across deferred_free_tick+0x7e
 * (the ring[i].ttl read in the loop body) and deferred_free_enqueue
 * +0x89 (the ring[i].ptr == NULL slot scan).
 */
static bool ring_unlock(void)
{
	if (mprotect(ring, ring_bytes, PROT_READ | PROT_WRITE) != 0) {
		outputerr("deferred_free: mprotect RW failed: errno=%d\n", errno);
		return false;
	}
	return true;
}

static void ring_lock(void)
{
	if (mprotect(ring, ring_bytes, PROT_NONE) != 0)
		outputerr("deferred_free: mprotect NONE failed: errno=%d\n", errno);
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
	 * Cache the brk-arena extent now, before any child forks.  Every
	 * child inherits the bounds via COW BSS so is_in_glibc_heap()
	 * needs no further /proc/self/maps reads at runtime.  Read here
	 * rather than at use-site: a syscall fuzzer parsing /proc on
	 * every deferred_free_enqueue would dwarf the work it's gating.
	 */
	heap_bounds_init();
}

void deferred_free_enqueue(void *ptr)
{
	unsigned int i;

	if (ptr == NULL)
		return;

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
	if (((unsigned long)ptr & 0x7) != 0) {
		static unsigned long misalign_drops;
		unsigned long n = ++misalign_drops;
		if ((n % 1000) == 1) {
			char pcbuf[128];
			outputerr("deferred_free_enqueue: rejected misaligned "
				  "ptr=%p caller=%s [%lu cumulative]\n", ptr,
				  pc_to_string(__builtin_return_address(0),
					       pcbuf, sizeof(pcbuf)), n);
		}
		return;
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
	if (is_corrupt_ptr_shape(ptr)) {
		outputerr("deferred_free_enqueue: rejected suspicious ptr=%p "
			  "(pid-scribbled?)\n", ptr);
		deferred_free_reject_bump(__builtin_return_address(0));
		return;
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
	if (!is_in_glibc_heap(ptr)) {
		static unsigned long non_heap_drops;
		unsigned long n = ++non_heap_drops;
		if ((n % 1000) == 1) {
			char pcbuf[128];
			outputerr("deferred_free_enqueue: rejected ptr=%p "
				  "(outside glibc heap) caller=%s "
				  "[%lu cumulative]\n", ptr,
				  pc_to_string(__builtin_return_address(0),
					       pcbuf, sizeof(pcbuf)), n);
		}
		{
			struct childdata *c = this_child();

			if (c != NULL && c->stats_ring != NULL)
				stats_ring_enqueue(c->stats_ring,
						   STATS_FIELD_SNAPSHOT_NON_HEAP_REJECT,
						   0, 1);
			else
				parent_stats.snapshot_non_heap_reject++;
		}
		return;
	}

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
				  pc_to_string(__builtin_return_address(0),
					       pcbuf, sizeof(pcbuf)), n);
		}
		deferred_free_reject_bump(__builtin_return_address(0));
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
				  pc_to_string(__builtin_return_address(0),
					       pcbuf, sizeof(pcbuf)), n);
		}
		return;
	}

	/* If ring_unlock() fails the page stays PROT_NONE; falling
	 * through into the slot scan would SEGV_ACCERR.  Free the ptr
	 * directly so the caller's contract (ptr is no longer their
	 * problem) still holds. */
	if (!ring_unlock()) {
		free(ptr);
		return;
	}

	/* If the ring is full, force-free the oldest (lowest TTL) entry
	 * to make room.  In practice this rarely happens — TTL range
	 * is 5-50 and we tick every syscall. */
	if (ring_count == DEFERRED_RING_SIZE) {
		unsigned int oldest = 0;
		unsigned int min_ttl = UINT_MAX;

		for (i = 0; i < DEFERRED_RING_SIZE; i++) {
			if (ring[i].ptr != NULL && ring[i].ttl < min_ttl) {
				min_ttl = ring[i].ttl;
				oldest = i;
			}
		}
		if (ring[oldest].ptr != NULL) {
			void *evict_ptr = ring[oldest].ptr;
			bool corrupt = false;

			/*
			 * The enqueue path validates ptr against the heap-
			 * bounds and shared-region bands BEFORE ring_unlock().
			 * Once unlocked, the slot sits RW until ring_lock()
			 * runs, so an in-flight stomp from a sibling fuzzed
			 * value-result syscall can scribble ring[oldest].ptr
			 * between when the slot was last validated and when
			 * the full-ring eviction here decides to free it.
			 * Re-run the surviving stateless guards before
			 * free()ing so a wild pointer becomes a telemetry
			 * bump instead of a crash.  alloc_track_consume()
			 * already fired at enqueue and would always miss
			 * here -- skipped, not re-run.  Counter only (no
			 * per-rejection log): the eviction case is rarer
			 * than the enqueue rejection paths, whose 1-in-1000
			 * caller-PC logs already prove the stomp pattern.
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
				free(evict_ptr);
			}
			ring[oldest].ptr = NULL;
			occupied_mask &= ~(1ULL << oldest);
			ring_count--;
		}
	}

	/* Find an empty slot.  After the full-ring eviction above, at
	 * least one bit in occupied_mask is clear, so ~occupied_mask is
	 * non-zero and __builtin_ctzll's UB-on-zero case can't fire. */
	i = __builtin_ctzll(~occupied_mask);
	ring[i].ptr = ptr;
	ring[i].ttl = RAND_RANGE(DEFERRED_TTL_MIN, DEFERRED_TTL_MAX);
	occupied_mask |= 1ULL << i;
	ring_count++;

	ring_lock();
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
 * alloc_track_consume already fired at enqueue and removed @ptr from
 * both the 256-slot ring and its 1024-slot hash mirror, so we cannot
 * re-run the consuming side.  We CAN re-probe the hash mirror via the
 * non-consuming alloc_track_lookup(): for an in-ring stomp that
 * scribbled @ptr to a value we never allocated, the lookup misses and
 * we reject.  Cost is one Fibonacci-hash plus a short linear probe --
 * a couple of cache lines worst case, negligible against the surrounding
 * mprotect bracket.
 *
 * Bumps STATS_FIELD_DEFERRED_FREE_CORRUPT_PTR (or its parent
 * fallback) on any rejection, matching the existing pattern; the
 * specific gate that fired shows up in the outputerr log line.
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
	else if (!alloc_track_lookup(ptr))
		reason = "alloc-track-miss";

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

	free(ptr);
}

void deferred_free_tick(void)
{
	static unsigned int tick_count;
	unsigned int i;

	/* Cheap path: ring_count is read while still locked, but it lives
	 * in BSS (not in the protected ring), so this access is safe. */
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

	/* On unlock failure the page is still PROT_NONE; bail rather
	 * than SEGV_ACCERR in the loop below.  Entries stay queued and
	 * will be retried on the next tick. */
	if (!ring_unlock())
		return;

	for (i = 0; i < DEFERRED_RING_SIZE; i++) {
		void *ptr;

		if (ring[i].ptr == NULL)
			continue;

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

	ring_lock();
}

void deferred_free_flush(void)
{
	unsigned int i;

	/* Called from the child exit path; if unlock fails the deferred
	 * ptrs leak, but the child is going away so the kernel reaps
	 * them at exit.  Better than SEGV_ACCERR-ing on the way out. */
	if (!ring_unlock())
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
