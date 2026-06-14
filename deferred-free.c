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
 * Each queue entry is 16 bytes on 64-bit (a pointer plus an unsigned
 * int ttl).  Membership tests go through a side hash rather than a
 * linear walk of the queue, so the per-tick overhead stays negligible
 * even though children do millions of syscalls.
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
#include "rnd.h"
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

/*
 * Per-slot provenance, stamped at admission and validated at every
 * free-gate.  ring[slot].ptr is what the slot was originally admitted
 * with AND what the slot currently holds; if a sibling fuzzed value-
 * result syscall scribbles ring[slot].ptr inside an open ring_unlock
 * bracket, ptr will diverge from base and the slot-cookie gate
 * (slot_owns) will refuse the free.  cookie = mk_cookie(base, gen,
 * slot, rc->cookie_secret) so scribbles of base / gen / cookie also
 * fail the recomputation; the per-init secret makes a self-consistent
 * three-field stomp astronomically unlikely.  gen is per-slot
 * (bumped on every admission) so a re-admission to the same slot
 * never collides with a stale cookie from a prior tenant.
 */
struct deferred_entry {
	void *ptr;
	void *base;
	unsigned long cookie;
	unsigned int ttl;
	unsigned int gen;
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
 * -- well under a hundred in the worst case.  4096 entries gives ample
 * headroom; on overflow we evict in arrival order, which only causes a
 * benign drop (memory leak) of the evicted pointer's eventual free.
 * Narrowing the input set to the opt-in subset keeps init-time and
 * per-child-table zmallocs out of the ring entirely.
 *
 * Process-local: zero-initialised BSS, COW-shared at fork, written
 * single-threaded by the owning child.  No locking needed.
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
 * Side-set membership accelerator for alloc_track[].
 *
 * alloc_track_consume() and alloc_track_lookup() resolve membership
 * through this 16384-slot hash (0.25 load factor at full occupancy),
 * so both hit and miss are O(1).  A fast miss matters: misses are the
 * path that fires when a scribbled snapshot field arrives at
 * deferred_free_enqueue, which is exactly the case where we want a
 * fast reject.
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
 * so the modulo collapses to a bitmask.  Storage shares the alloc_track
 * mmap region (see alloc_track declaration above) so one mprotect
 * bracket covers both arrays.  Slots DO hold pointer values an attacker
 * can turn into a free() target -- alloc_track_lookup gates
 * cleanup_release_post_state -> tracked_free_now -> free() and
 * alloc_track_consume admits values into the deferred ring -- so the
 * PROT_READ steady state is load-bearing for memory safety, not just
 * a perf nicety.  Mirror the ring[]/inflight_hash[] armor pattern.
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
 * In-flight pointer set: mirrors "currently admitted to the deferred
 * ring" membership.  Separate from alloc_track_hash[] (which tracks
 * the broader "deferred-free-eligible alloc side-set" populated by
 * zmalloc_tracked() and drained by alloc_track_consume), so the two
 * lifecycles don't conflict.
 *
 * Populated at the tail of deferred_free_enqueue after the ring slot
 * write succeeds; cleared at the tail of free_ring_entry on the
 * successful free() path.  Telemetry-only mirror in this commit:
 * the in-flight-miss gate that previously consulted this set in
 * ring_evict_oldest_safe and free_ring_entry was a value-keyed
 * shadow that stale-positived under VMA-pressure mprotect failures
 * and between GC sweeps, letting a sibling-scribbled ring slot whose
 * new value matched a stale-positive entry reach free() (the ASAN
 * bad-free class fixed by this commit).  Both gates now read the
 * authoritative per-slot provenance via slot_owns() instead.  The
 * set is retained so the inflight_gc_sweep orphan-rate counter
 * still reflects how often stomps leave the in-flight mirror out of
 * sync with ring[] -- a useful telemetry signal even though it no
 * longer participates in any free-decision gate.
 *
 * Storage shape mirrors alloc_track_hash[] (1024 slots, Fibonacci
 * index, open-addressed with shift-back deletion).  Sized for the
 * 64-slot ring plus headroom for stomp orphans accumulated between
 * GC sweeps; an idle slot costs 8 bytes of the mmap'd backing.
 *
 * Storage lives in an mmap'd region whose address range is registered
 * with shared_regions[] via track_shared_region(), mirroring ring[]'s
 * shape.  Steady state is PROT_READ; inflight_gc_sweep reads the
 * array directly against that steady state once every 16K syscalls
 * and is the only reader.  Writers (inflight_hash_insert /
 * inflight_hash_remove / the dispose-time clear) bracket their
 * mutations with inflight_unlock()/inflight_lock() so a sibling
 * fuzzed value-result syscall that aliases the set's pages between
 * writes hits the PROT_READ wall instead of silently flipping a
 * membership bit.
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

void deferred_alloc_track(void *ptr)
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
			alloc_track_hash_remove(ptr);
			alloc_track_lock();
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
 * unrelated tracked allocations faster than any fixed ALLOC_TRACK_SIZE can
 * absorb at full throughput.  Refreshing the LRU position on reuse keeps a
 * long-lived dedup'd entry resident regardless of churn rate.
 */
void alloc_track_refresh(void *ptr)
{
	if (ptr == NULL)
		return;
	(void)alloc_track_consume(ptr);
	deferred_alloc_track(ptr);
}

/*
 * Ring storage lives in an mmap'd region whose address range is registered
 * with shared_regions[] via track_shared_region().  That tracking lets
 * avoid_shared_buffer() and the mm-syscall sanitisers refuse fuzzed
 * pointers/lengths that would land inside the ring -- previously the array
 * lived in trinity's BSS, which is NOT registered with shared_regions[],
 * so a fuzzed write could scribble ring[i].ptr with a pid-shaped value
 * and the next deferred_free_tick() would free() the bogus pointer.
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
	/*
	 * Per-init random mix folded into every slot cookie.  Stored in
	 * the same armored page as ring/ring_bytes/ring_count so a
	 * scribble that wants to forge a cookie has to land here at
	 * PROT_READ and hit the SIGSEGV-on-write wall.  Per-init means
	 * the secret is COW'd into every forked child but does not leak
	 * across unrelated trinity runs -- a coincidental cookie match
	 * from a prior run cannot replay.
	 */
	unsigned long cookie_secret;
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
 * Bracket every writer/reader of ring[] with mprotect().  Between
 * ticks the ring sits at PROT_NONE; any fuzzed value-result syscall
 * that tries to scribble inside it now SIGSEGVs in the kernel's
 * copy_from_user instead of silently overwriting ring[i].ptr with a
 * pid-shaped value.  mprotect is async-signal-safe so these are safe
 * to call from anywhere deferred_free_* is reachable.
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
 * either way the caller bails before touching ring[].  Distinguishing
 * the three cases is load-bearing: collapsing them into a single
 * logged-and-return path leaves the ring PROT_NONE while the caller
 * falls through, turning queued pages into SEGV_ACCERR bait for
 * sibling value-result syscalls and leaking the queued ptrs.  The
 * current routing keeps the page PROT_NONE (no caller proceeds on
 * failure) but stops adding queue pressure while the kernel is at the
 * VMA limit.
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
 * Per-slot integrity tag computed from (base, gen, slot, secret).
 * Stamped at admission, validated at every free-gate.  A scribble of
 * any of base / gen / cookie -- or a scribble of ring[i].ptr that
 * makes ptr diverge from base -- fails the recomputation and the
 * slot is rejected.  The per-init secret (rc->cookie_secret) makes a
 * coherent three-field stomp astronomically unlikely.  Pure function
 * over its inputs; caller must hold rc-readable steady state (which
 * is the default -- rc is PROT_READ outside writer brackets).
 *
 * Constants: 0x9E3779B97F4A7C15ULL is 2^64/phi (the same Fibonacci
 * multiplier used by alloc_track_hash_index for pointer-stream
 * scattering); a 16-bit shift on slot keeps slot bits out of the
 * gen-product low bits so each ring position's cookies live in a
 * distinct sub-range.
 */
static inline unsigned long mk_cookie(void *base, unsigned int gen,
				      unsigned int slot)
{
	uint64_t k = (uint64_t)(uintptr_t)base;

	k ^= (uint64_t)gen * 0x9E3779B97F4A7C15ULL;
	k ^= (uint64_t)slot << 16;
	k ^= rc->cookie_secret;
	return (unsigned long)k;
}

/*
 * Does ring[slot] still legitimately own the base pointer it was
 * admitted with?  Reads only ring[] (mprotect-armored, registered
 * with shared_regions[], the authoritative source of slot ownership)
 * and rc->cookie_secret (PROT_READ-armored same as the rest of rc).
 *
 * NO consultation of inflight_hash, no shadow lookup.  The previous
 * eviction and TTL-drain gates routed through
 * inflight_hash_contains(), a value-keyed mirror that stale-positives
 * when (a) tracked_free_now frees a tracked chunk WITHOUT calling
 * inflight_hash_remove (path documented above tracked_free_now), or
 * (b) the GC sweep has not yet reconciled orphaned in-flight entries
 * from a prior in-ring stomp.  Either lie let a sibling-scribbled
 * ring slot whose new value happened to match a stale-positive entry
 * pass the gate and reach free() -- an ASAN bad-free against a
 * chunk already returned to the arena.  Per-slot provenance is
 * immune to both desync vectors: a scribble that does not also
 * coherently restamp base+gen+cookie fails the recomputation.
 *
 * Caller must hold the ring_unlock() bracket (ring[] is PROT_NONE at
 * rest).  rc is PROT_READ steady-state, no bracket needed for the
 * secret read.
 */
static bool slot_owns(unsigned int slot)
{
	void *p = ring[slot].ptr;

	if (p == NULL)
		return false;
	if (p != ring[slot].base)
		return false;
	if (ring[slot].cookie != mk_cookie(p, ring[slot].gen, slot))
		return false;
	return true;
}

/*
 * Does ANY ring slot legitimately own @ptr?  Scans ring[].base rather
 * than ring[].ptr so a sibling scribble of ring[i].ptr to some
 * unrelated value does not fool the check -- the slot still owns the
 * original base, and TTL-drain will reject the scribbled .ptr at
 * free_ring_entry's slot-cookie gate.  Used by tracked_free_now to
 * decide whether the deferred ring is about to free @ptr (skip the
 * sync free) or has nothing pinned for @ptr (proceed with the sync
 * free).  Caller must hold ring_unlock().
 */
static bool ring_owns_ptr(void *ptr)
{
	unsigned int i;

	for (i = 0; i < DEFERRED_RING_SIZE; i++) {
		if (ring[i].base == ptr && slot_owns(i))
			return true;
	}
	return false;
}

/*
 * Rate-limited breadcrumb for slot-cookie rejects.  One log line per
 * 1000 rejects mirrors the other deferred_free_reject_* logs so a
 * stomp surge is loud but a steady rate does not flood the output
 * channel.  Always bumps the headline counter; the log line is the
 * secondary breadcrumb that ties a future ASAN bad-free (had we
 * freed) to the slot + ptr that would have been the target.  Caller
 * may hold or release the ring_unlock() bracket -- the helper does
 * not touch ring[].
 */
static void deferred_free_slot_reject(unsigned int slot, void *ptr,
				      const char *site)
{
	static unsigned long rejects;
	unsigned long n;

	__atomic_add_fetch(&shm->stats.deferred_free_slot_cookie_mismatch,
			   1, __ATOMIC_RELAXED);
	n = ++rejects;
	if ((n % 1000) == 1) {
		outputerr("deferred_free: slot-cookie reject site=%s "
			  "slot=%u ptr=%p ring_count=%u occupied=0x%llx "
			  "[%lu cumulative]\n", site, slot, ptr,
			  ring_count, (unsigned long long)occupied_mask, n);
	}
}

/*
 * Legacy "any slot currently holds this ptr value" probe.  Kept as a
 * thin wrapper over the ring scan for the enqueue admission-dedup
 * gate, whose semantics are intentionally permissive: a slot whose
 * .ptr happens to match @ptr is treated as already-admitted even if
 * its base/cookie no longer validate, so we do not allocate a second
 * slot for the same value.  The other three free-gates use
 * slot_owns() / ring_owns_ptr() for the stricter provenance check.
 *
 * The caller must already hold the ring_unlock() bracket: ring[] is
 * PROT_NONE at rest, so an unbracketed read would SIGSEGV.  Splitting
 * the bracket out of this helper lets callers that are already inside
 * an open ring_unlock() window (deferred_free_enqueue_internal's
 * admission-dedup, after the unlock + before the matching ring_lock)
 * skip a second mprotect pair.
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
 * Ring-ownership gate: scan ring[] directly to decide whether @ptr
 * is currently pinned in the deferred-free ring.  ring[] is the
 * source-of-truth (mprotect-armored AND registered with
 * shared_regions[], so neither scribble nor mprotect-failure can
 * desync it from itself).  Uses the per-slot provenance probe
 * ring_owns_ptr(): a slot only registers as owning @ptr if its
 * recorded .base == @ptr AND the cookie validates against the
 * recorded .gen + slot + per-init secret.  This is strictly tighter
 * than a bare ring[i].ptr == @ptr scan: a scribble that overwrote
 * a slot's .ptr to coincidentally match @ptr no longer fools the
 * check (the slot's base still records the original admission, so
 * base != @ptr); and a scribble that overwrote .base / .gen /
 * .cookie fails the cookie recomputation.  Either way the slot is
 * NOT treated as owning @ptr, the sync free proceeds, and the
 * scribbled slot will be rejected at TTL-drain by free_ring_entry's
 * slot-cookie gate -- exactly the symmetry that prevents the
 * double-free this commit's mate addresses on the eviction side.
 *
 * Cost: ring_count > 0 gate (read against rc's PROT_READ steady
 * state -- no syscall); on the non-empty path, one ring_unlock pair
 * plus a 64-slot scan.  Acceptable on the cleanup boundary.
 *
 * ring_unlock() failure (ENOMEM) cannot verify residency -- leak @ptr
 * rather than risk a double-free; child exit reclaims it.  Bumps
 * deferred_free_tracked_free_unverified_leak so the rate is
 * observable.
 */
void tracked_free_now(void *ptr)
{
	bool ring_owned = false;

	if (ptr == NULL)
		return;

	alloc_track_consume(ptr);

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
	 */
	if (ring != NULL) {
		if (ring_unlock() != RING_UNLOCK_OK) {
			__atomic_add_fetch(&shm->stats.deferred_free_tracked_free_unverified_leak,
					   1, __ATOMIC_RELAXED);
			return;
		}
		ring_owned = ring_owns_ptr(ptr);
		ring_lock();
	}

	if (ring_owned) {
		__atomic_add_fetch(&shm->stats.deferred_free_ring_owned_skip,
				   1, __ATOMIC_RELAXED);
		return;
	}

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
		__atomic_add_fetch(&shm->stats.deferred_free_reject_non_heap,
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
		__atomic_add_fetch(&shm->stats.deferred_free_reject_shared_region,
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
 * ENOMEM and emits another "mprotect RW failed" line.
 *
 * Releasing the VMA slot with munmap() drops both failure modes at the
 * source: the PROT_NONE residue is gone (so no more SEGV_ACCERR fault-
 * bait), and the kernel gets the VMA back to satisfy whatever split the
 * wider mm-syscall workload needed.  Cost: every ptr currently in the
 * ring is leaked from glibc's tracking until the child exits.  That is
 * the same tradeoff the drain-aggressive bypass already accepted for
 * the per-allocation UAF-detection window -- abandoning the remaining
 * ring slots is the worst case of that bypass, taken once when the
 * kernel has actually told us it cannot satisfy more mprotect splits.
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
	const size_t inflight_raw = sizeof(void *) * INFLIGHT_HASH_SIZE;
	const size_t at_raw = sizeof(void *) *
		(ALLOC_TRACK_SIZE + ALLOC_TRACK_HASH_SIZE);
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
	/*
	 * Per-init random secret that mk_cookie() folds into every slot
	 * cookie.  Sampled before rc_lock() so a scribbler in a sibling
	 * fuzzed value-result syscall cannot brute-force a coherent
	 * three-field stomp without first guessing this value.  Seeded
	 * once in the parent and COW'd into every forked child, matching
	 * the ring's COW-private contract; deferred_free_init runs after
	 * create_shm()'s init_seed() so rnd_state is already live.
	 */
	rc->cookie_secret = rnd_u64();
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
	__atomic_add_fetch(&shm->stats.deferred_free_reject_misaligned, 1, __ATOMIC_RELAXED);
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
	bool gate_pass;

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
	 * Per-slot provenance gate: free only if the slot's recorded
	 * base+gen+cookie still validate -- i.e. the slot is unchanged
	 * since admission.  Reads only ring[] (mprotect-armored AND
	 * registered with shared_regions[], the authoritative source of
	 * slot ownership); the previous inflight_hash_contains() check
	 * was a value-keyed shadow that could stale-positive when a
	 * sibling fuzzed value-result syscall scribbled ring[oldest].ptr
	 * to some value that coincidentally matched a stale-positive
	 * entry, letting eviction free a chunk already returned to the
	 * arena (ASAN bad-free; the original root cause this commit
	 * addresses).
	 *
	 * Keep is_in_glibc_heap / range_overlaps_shared as belt-and-
	 * suspenders: cheap and catches the theoretical case where the
	 * ring's own armor failed to detect a scribble that landed
	 * inside the writer's RW bracket.  alloc_track_consume() already
	 * fired at enqueue and would always miss here -- skipped, not
	 * re-run.
	 *
	 * On reject we LEAK the candidate (child exit reclaims) rather
	 * than free() it: under ASAN the leak preserves the bad-free
	 * report we would otherwise synthesise, and in any build the
	 * safer direction to err is "do not free a value the slot can
	 * no longer prove was the admitted pointer."  The 1-in-1000
	 * breadcrumb captures slot + ptr + ring_count so a future
	 * audit can tie a missed-free to the slot whose stomp caused
	 * the reject.
	 */
	{
		bool cookie_ok = slot_owns(oldest);

		gate_pass = cookie_ok &&
			    is_in_glibc_heap(evict_ptr) &&
			    !range_overlaps_shared((unsigned long)evict_ptr, 1);
		if (gate_pass) {
			inflight_hash_remove(evict_ptr);
			free(evict_ptr);
		} else {
			struct childdata *c = this_child();

			if (!cookie_ok)
				deferred_free_slot_reject(oldest, evict_ptr,
							  "evict");
			if (c != NULL && c->stats_ring != NULL)
				stats_ring_enqueue(c->stats_ring,
						   STATS_FIELD_RING_EVICTION_CORRUPT,
						   0, 1);
			else
				parent_stats.ring_eviction_corrupt++;
		}
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

	/*
	 * Admission dedup: refuse to take a second slot for a ptr that
	 * already owns one.  alloc_track_consume() above does not know
	 * about ring residency -- alloc_track_refresh() can re-admit a
	 * ring-resident ptr to alloc_track, after which the next enqueue
	 * of that ptr passes consume() a second time and would otherwise
	 * land in a fresh ring slot.  Two slots holding the same value is
	 * the reuse-mediated double-free shape: slot A's TTL fires and
	 * free()s @ptr; the address is reused by a new alloc; slot B's
	 * TTL fires and free()s the new owner's chunk.  ring[] is the
	 * source-of-truth (inflight_hash is value-keyed and desyncs under
	 * VMA-pressure mprotect failures), so scan it directly.  The
	 * ring_unlock bracket above is still open, so this is just a 64-
	 * compare scan, no additional mprotect.  Re-lock and bail on hit.
	 */
	if (ring_contains(ptr)) {
		ring_lock();
		__atomic_add_fetch(&shm->stats.deferred_free_double_admit_skip,
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
	/*
	 * Stamp the slot's per-admission provenance under the existing
	 * ring_unlock() bracket so the four payload fields land in
	 * lock-step.  base captures the admitted pointer for the
	 * eventual ptr==base check; gen bumps per-admission so a
	 * re-tenant of the same slot never collides with a stale
	 * cookie; cookie is the integrity tag over (base, gen, slot,
	 * secret).  A sibling fuzzed value-result syscall that scribbles
	 * ring[i].ptr after this point fails ptr==base; a stomp that
	 * also rewrites ring[i].base fails the cookie recomputation
	 * (unless it also coherently restamps gen + cookie + matches
	 * the per-init secret -- astronomically unlikely).
	 */
	ring[i].ptr = ptr;
	ring[i].base = ptr;
	ring[i].gen += 1;
	ring[i].cookie = mk_cookie(ptr, ring[i].gen, i);
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
 * Free one ring entry's payload, dropping it if the slot's provenance
 * (base / gen / cookie) fails the slot-cookie gate or the stateless
 * bands.  Both the tick (TTL expiry) and flush (child exit) paths
 * route through here -- pre-helper, only tick had these checks, so a
 * corrupted ring entry surviving until child exit would silently free
 * a bogus pointer through deferred_free_flush().  The tick guard
 * rejected ~47.7k corrupt-pointer scribbles in a single 6.76h run
 * (~2/sec), so the ring DOES get scribbled in practice; every entry
 * the tick guard would have rejected was being silently freed by
 * flush instead.
 *
 * Caller captures (ptr, base, cookie, gen, slot) from ring[slot]
 * BEFORE clearing ring[slot].ptr and passes the snapshot in.
 * Clearing first means a signal that longjmps out of free() can't
 * leave a freed pointer pending in the ring; capturing the snapshot
 * first is necessary because the slot-cookie gate validates the
 * captured base/cookie/gen against the captured ptr, and the post-
 * clear ring[slot] no longer has them.
 *
 * Gates in order:
 *   1. slot-cookie: ptr must equal base AND cookie must validate
 *      against (base, gen, slot, secret).  This is the authoritative
 *      check -- a scribble that touched any of base / gen / cookie /
 *      or ptr fails here.  Reads only the captured snapshot; no
 *      shadow-hash lookup.  Replaces the previous
 *      inflight_hash_contains() gate, which was a value-keyed mirror
 *      that stale-positived under VMA-pressure mprotect failures or
 *      between GC sweeps and let a coincidentally-heap-shaped stomp
 *      reach free() (the ASAN bad-free class this commit's mate
 *      eviction fix addresses).
 *   2. stateless belt-and-suspenders: shape (pid-scribbled / sub-page
 *      / non-canonical / misaligned), heap-bounds, shared-region
 *      overlap.  Cheap; catches the theoretical case where the ring's
 *      armor itself failed to detect a scribble that landed inside a
 *      writer's RW bracket.
 *
 * alloc_track_consume already fired at enqueue and would always miss
 * here -- skipped, not re-run.
 *
 * On reject we LEAK the candidate (child exit reclaims): under ASAN
 * the leak preserves the bad-free report we would otherwise
 * synthesise, and in any build the safer direction to err is "do not
 * free a value the slot can no longer prove was the admitted
 * pointer."  Bumps the headline slot-cookie-mismatch counter via
 * deferred_free_slot_reject() AND the legacy
 * deferred_free_corrupt_ptr counter so existing dashboards continue
 * to see the per-event rate.
 *
 * On the clean-free path the entry is removed from inflight_hash so
 * the GC sweep does not later mistake it for an orphan -- the hash
 * stays a telemetry-only mirror in this commit (Design Fork A
 * default: drop the gate but keep the orphan-rate counter).
 */
static void free_ring_entry(void *ptr, void *base, unsigned long cookie,
			    unsigned int gen, unsigned int slot)
{
	struct childdata *c;
	const char *reason = NULL;
	bool cookie_reject = false;

	if (ptr == NULL || ptr != base ||
	    cookie != mk_cookie(base, gen, slot)) {
		reason = "slot-cookie";
		cookie_reject = true;
	} else if (is_corrupt_ptr_shape(ptr)) {
		reason = "shape";
	} else if (!is_in_glibc_heap(ptr)) {
		reason = "non-heap";
	} else if (range_overlaps_shared((unsigned long)ptr, 1)) {
		reason = "shared-region";
	}

	if (reason != NULL) {
		c = this_child();
		if (cookie_reject)
			deferred_free_slot_reject(slot, ptr, "free-ring");
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
		__atomic_add_fetch(&shm->stats.deferred_free_rw_restore_enomem,
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

		/* TTL expired — free it.  Capture the slot's per-
		 * admission provenance (base/cookie/gen) BEFORE clearing
		 * ring[i].ptr so the slot-cookie gate inside
		 * free_ring_entry can validate the captured snapshot.
		 * Clearing the slot before calling free() keeps the
		 * signal-mid-free + longjmp window safe: even if the
		 * free() never returns, the slot is already empty so
		 * the next tick can't re-free it. */
		{
			void *base = ring[i].base;
			unsigned long cookie = ring[i].cookie;
			unsigned int gen = ring[i].gen;

			ptr = ring[i].ptr;
			ring[i].ptr = NULL;
			occupied_mask &= ~(1ULL << i);
			ring_count--;

			free_ring_entry(ptr, base, cookie, gen, i);
		}
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
		__atomic_add_fetch(&shm->stats.deferred_free_rw_restore_enomem,
				   1, __ATOMIC_RELAXED);
		ring_dispose_after_enomem();
		return;
	}
	if (r != RING_UNLOCK_OK)
		return;

	for (i = 0; i < DEFERRED_RING_SIZE; i++) {
		void *ptr;
		void *base;
		unsigned long cookie;
		unsigned int gen;

		if (ring[i].ptr == NULL)
			continue;

		/* Capture provenance before clearing; mirror the tick
		 * path's signal-mid-free safety AND the slot-cookie
		 * gate's snapshot contract.  See free_ring_entry. */
		base = ring[i].base;
		cookie = ring[i].cookie;
		gen = ring[i].gen;
		ptr = ring[i].ptr;
		ring[i].ptr = NULL;
		free_ring_entry(ptr, base, cookie, gen, i);
	}
	if (rc_unlock() == 0) {
		ring_count = 0;
		rc_lock();
	}
	occupied_mask = 0;

	ring_lock();
}
