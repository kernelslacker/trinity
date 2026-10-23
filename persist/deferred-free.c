/*
 * Deferred-free queue: hold syscall-owned allocations for 5-50 more syscalls
 * instead of freeing them at return, so multiple allocations overlap in time
 * and expose kernel UAF / stale-ref / double-free.  The alloc_track side-set,
 * generation arena, protected regions and per-record release live in the
 * deferred-free-*.c siblings.
 */

#include <errno.h>
#include <limits.h>
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

#include "deferred-free-internal.h"

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
 * Is @ptr currently pinned in the deferred-free ring?  Linear scan of
 * the 64 slots; cheap (64 cache-resident pointer compares) and definitive
 * because ring[] is the source-of-truth for ring residency.
 *
 * The caller must already hold the df_ring_unlock() bracket: ring[] is
 * PROT_NONE at rest, so an unbracketed read would SIGSEGV.  Splitting
 * the bracket out of this helper lets callers that are already inside
 * an open df_ring_unlock() window (deferred_free_enqueue_internal's
 * admission-dedup, after the unlock + before the matching df_ring_lock)
 * skip a second mprotect pair.  Callers that don't already hold the
 * bracket (tracked_free_now) take it themselves before calling.
 */
static bool ring_contains(void *ptr)
{
	unsigned int i;

	for (i = 0; i < DEFERRED_RING_SIZE; i++) {
		if (df_rc->ring[i].ptr == ptr)
			return true;
	}
	return false;
}

/*
 * Refresh a tracked entry's LRU position (consume + re-insert at head)
 * so long-lived dedup'd anon-pool entries don't rotate out under
 * unrelated tracked-alloc churn.  Skip when @ptr is ring- or
 * arena-resident: the ring owns the lifecycle and a fresh alloc_track
 * entry would become a stale survivor that outlives the ring's drain and
 * arms an address-reuse bad-free.  df_ring_unlock failure -> skip (cannot
 * verify residency safely).  See Documentation/deferred-free.md
 * "alloc_track_refresh" for the full desync analysis.
 */
void alloc_track_refresh(void *ptr)
{
	bool ring_owned = false;
	size_t size;

	if (ptr == NULL)
		return;

	if (df_rc->ring != NULL) {
		if (df_ring_unlock() != RING_UNLOCK_OK) {
			__atomic_add_fetch(&shm->stats.deferred_free.alloc_track_refresh_unverified_skip,
					   1, __ATOMIC_RELAXED);
			return;
		}
		ring_owned = ring_contains(ptr);
		df_ring_lock();
	}

	if (ring_owned || df_gen_arena_contains(ptr)) {
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
	if (!df_alloc_track_consume(ptr)) {
		__atomic_add_fetch(&shm->stats.deferred_free.alloc_track_refresh_consume_miss,
				   1, __ATOMIC_RELAXED);
		return;
	}
	deferred_alloc_track(ptr, size);
}

/*
 * Synchronously free a zmalloc_tracked() pointer, skipping when @ptr is
 * ring- or arena-resident (the ring owns the free-time consume, or the
 * generation it evicted @ptr into does).  Ring-ownership check scans
 * ring[] directly (source of truth); the previous value-keyed mirror
 * desynced under ENOMEM and stomp pressure and armed a reuse-mediated
 * double-free.  df_ring_unlock ENOMEM -> leak @ptr rather than risk it.
 * See Documentation/deferred-free.md "tracked_free_now ring-residency
 * check".
 */
void tracked_free_now(void *ptr)
{
	bool ring_owned = false;

	if (ptr == NULL)
		return;

	/*
	 * Gate on ring != NULL, not occupied_mask != 0.  Even now that
	 * occupied_mask shares the armored ring_control page (see the
	 * struct comment), the RW window opened by df_rc_unlock() during
	 * eviction/enqueue/drain lets a sibling fuzzed value-result
	 * syscall land inside; a mask-driven gate would still be
	 * skippable within that window and would then let this function
	 * free() a ring-resident chunk, which eviction or TTL would free
	 * a second time.  ring is set once at init and cleared only by
	 * df_ring_dispose_after_enomem(); both writers go through
	 * df_rc_unlock()'s armored bracket, so the pointer cannot lie about
	 * ring liveness.  Always run the armored ring[] scan whenever
	 * the ring still exists.
	 *
	 * Ring residency check runs BEFORE df_alloc_track_consume:
	 * alloc_track is now populated through ring residency (the
	 * enqueue gate uses non-consuming alloc_track_lookup; consume is
	 * deferred to free_ring_entry, or to gen_arena_retire_one for an
	 * evicted ptr).  Consuming here when the ring owns the ptr would
	 * strip the alloc_track entry that free-time gate relies on -- the
	 * subsequent drain or arena retire would consume-miss and leak the
	 * chunk instead of freeing it.  Skip the consume (and the free,
	 * which the ring or arena will perform) when ring-owned.
	 */
	if (df_rc->ring != NULL) {
		if (df_ring_unlock() != RING_UNLOCK_OK) {
			__atomic_add_fetch(&shm->stats.deferred_free.tracked_free_unverified_leak,
					   1, __ATOMIC_RELAXED);
			return;
		}
		ring_owned = ring_contains(ptr);
		df_ring_lock();
	}

	if (ring_owned || df_gen_arena_contains(ptr)) {
		__atomic_add_fetch(&shm->stats.deferred_free.ring_owned_skip,
				   1, __ATOMIC_RELAXED);
		return;
	}

	df_tracked_free_checked(ptr, TRACKED_FREE_SITE_IMMEDIATE);
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
/*
 * Compile-time guard: if DEFERRED_RING_SIZE ever grows to the point
 * where ring_count could reach g_max_vmas/2 under the default
 * max_map_count, this fires loudly instead of silently re-activating
 * a runtime check that has been dead since DEFERRED_RING_SIZE == 64.
 */
_Static_assert(DEFERRED_RING_SIZE * 2 <= DEFERRED_DEFAULT_MAX_VMAS,
	       "DEFERRED_RING_SIZE * 2 exceeds DEFERRED_DEFAULT_MAX_VMAS: "
	       "g_max_vmas/2 soft cap would activate before ring fills; "
	       "raise DEFERRED_DEFAULT_MAX_VMAS or revisit the cap formula");
static unsigned int g_max_vmas = DEFERRED_DEFAULT_MAX_VMAS;

void deferred_free_read_max_map_count(void)
{
	int fd;
	char buf[32];
	ssize_t n;
	long v;
	char *endp;

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
	errno = 0;
	v = strtol(buf, &endp, 10);
	if (errno == ERANGE || endp == buf || v <= 0 || v > INT_MAX) {
		outputerr("deferred_free: parse(/proc/sys/vm/max_map_count) "
			  "failed: \"%s\"; using default %u\n", buf, g_max_vmas);
		return;
	}
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

/*
 * Make room by moving the lowest-TTL entry into the generation arena.
 * Not a rare path: TTLs count batched ticks, so an entry lives 80-800
 * syscalls and the ring is typically full -- most enqueues evict.
 */
static void ring_evict_oldest_safe(void)
{
	unsigned int i;
	unsigned int oldest = 0;
	unsigned int min_ttl = UINT_MAX;
	void *evict_ptr;
	bool corrupt = false;

	for (i = 0; i < DEFERRED_RING_SIZE; i++) {
		if (df_rc->ring[i].ptr != NULL &&
		    df_rc->ring[i].ttl < min_ttl) {
			min_ttl = df_rc->ring[i].ttl;
			oldest = i;
		}
	}
	if (df_rc->ring[oldest].ptr == NULL)
		return;

	/*
	 * Clear the slot before handing the pointer on, as the tick drain
	 * does before free(): an interruption in between then leaks the
	 * chunk instead of leaving it owned by both the ring and the arena.
	 */
	evict_ptr = df_rc->ring[oldest].ptr;
	df_rc->ring[oldest].ptr = NULL;
	if (df_rc_unlock() == 0) {
		df_rc->occupied_mask &= ~(1ULL << oldest);
		df_rc->ring_count--;
		df_rc_lock();
	}

	/*
	 * Prefilter stays for telemetry granularity: a scribbled slot
	 * bumps ring_eviction_corrupt instead of feeding a corrupt value
	 * into the arena.  On clean shape the pointer is filed into the
	 * generation arena for bounded-hold retirement (see the arena
	 * definition above); an arena-pressure failure falls back to the
	 * historical leak-on-eviction path, bumping both ring_evict_leaked
	 * (the eviction-outcome headline) and gen_arena_pressure_leak (the
	 * arena-undersized signal).  alloc_track stays populated on the
	 * arena-admit path (retirement consumes at drain time); leaks
	 * likewise leave alloc_track populated so a later address-reuse
	 * enqueue of the same ptr is still recognised as owned.
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
		if (!df_gen_arena_push(evict_ptr)) {
			__atomic_add_fetch(&shm->stats.deferred_free.gen_arena_pressure_leak,
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.deferred_free.ring_evict_leaked,
					   1, __ATOMIC_RELAXED);
		}
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
	 * (free_ring_entry / gen_arena_retire_one).  Defer of the consume
	 * is what lets a stomp that swaps ring[i].ptr to an interior or
	 * stale heap-shaped value be rejected at free time -- the interior
	 * pointer matches no alloc_track slot, df_alloc_track_consume misses,
	 * and the slot is leaked instead of handed to free().  The
	 * companion free-time consume is in free_ring_entry and, for an
	 * evicted ptr, gen_arena_retire_one.
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
	 * This range check runs BEFORE df_ring_unlock() so we don't pay the
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
	 * A pointer the generation arena holds still passes the lookup
	 * above, and the ring_contains() dedup below cannot see it.  Refuse
	 * it here, ahead of the pressure fallbacks, which would otherwise
	 * free a chunk the arena still owns.
	 */
	if (df_gen_arena_contains(ptr)) {
		__atomic_add_fetch(&shm->stats.deferred_free.double_admit_skip,
				   1, __ATOMIC_RELAXED);
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
	 * The _Static_assert above DEFERRED_DEFAULT_MAX_VMAS ensures this
	 * check stays non-binding at compile time; it will fire loudly
	 * if DEFERRED_RING_SIZE ever grows past the half-budget threshold.
	 *
	 * Placed AFTER the alloc_track_lookup ownership gate so an
	 * untracked-ptr reject short-circuits before the VMA accounting,
	 * and BEFORE df_ring_unlock so the rejected enqueue does not pay
	 * the mprotect bracket cost.  The alloc_track entry stays
	 * populated through ring residency by design (consume is
	 * deferred to free_ring_entry / gen_arena_retire_one); the
	 * pressure-path immediate-free below routes around the ring and
	 * goes through df_tracked_free_checked() so its free() is gated on
	 * df_alloc_track_consume() success -- keeps the set in lock-step
	 * with the heap, and a consume-miss (lookup said yes earlier but
	 * the slot has since rotated out) bumps deferred_free_reject_
	 * untracked instead of being silently freed.
	 */
	if (df_rc->ring_count > g_max_vmas / 2) {
		__atomic_add_fetch(&shm->stats.deferred_free.vma_fallback_immediate,
				   1, __ATOMIC_RELAXED);
		if (leak_on_pressure) {
			__atomic_add_fetch(&shm->stats.deferred_free.pre_dispatch_leaked,
					   1, __ATOMIC_RELAXED);
		} else {
			df_tracked_free_checked(ptr,
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
	if (df_rc->ring == NULL) {
		if (leak_on_pressure) {
			__atomic_add_fetch(&shm->stats.deferred_free.pre_dispatch_leaked,
					   1, __ATOMIC_RELAXED);
		} else {
			df_tracked_free_checked(ptr,
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
	 * outputerr line from df_ring_unlock keeps the per-event log
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
	 * a VMA-budget event, and the next df_ring_unlock can plausibly
	 * succeed.
	 */
	{
		enum ring_unlock_result r = df_ring_unlock();

		if (r == RING_UNLOCK_ENOMEM) {
			__atomic_add_fetch(&shm->stats.deferred_free.enomem_drain,
					   1, __ATOMIC_RELAXED);
			df_ring_dispose_after_enomem();
			if (leak_on_pressure) {
				__atomic_add_fetch(&shm->stats.deferred_free.pre_dispatch_leaked,
						   1, __ATOMIC_RELAXED);
			} else {
				df_tracked_free_checked(ptr,
							TRACKED_FREE_SITE_IMMEDIATE);
			}
			return;
		}
		if (r != RING_UNLOCK_OK) {
			if (leak_on_pressure) {
				__atomic_add_fetch(&shm->stats.deferred_free.pre_dispatch_leaked,
						   1, __ATOMIC_RELAXED);
			} else {
				df_tracked_free_checked(ptr,
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
	 * is the source-of-truth, so scan it directly.  The df_ring_unlock
	 * bracket above is still open, so this is just a 64-compare
	 * scan, no additional mprotect.  Re-lock and bail on hit.
	 */
	if (ring_contains(ptr)) {
		df_ring_lock();
		__atomic_add_fetch(&shm->stats.deferred_free.double_admit_skip,
				   1, __ATOMIC_RELAXED);
		return;
	}

	if (df_rc->occupied_mask == ~0ULL)
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
	if (df_rc->occupied_mask == ~0ULL) {
		df_ring_lock();
		if (leak_on_pressure) {
			__atomic_add_fetch(&shm->stats.deferred_free.pre_dispatch_leaked,
					   1, __ATOMIC_RELAXED);
		} else {
			df_tracked_free_checked(ptr,
						TRACKED_FREE_SITE_IMMEDIATE);
		}
		return;
	}

	/* Find an empty slot.  After the full-ring eviction above, at
	 * least one bit in occupied_mask is clear, so ~occupied_mask is
	 * non-zero and __builtin_ctzll's UB-on-zero case can't fire. */
	i = __builtin_ctzll(~df_rc->occupied_mask);
	df_rc->ring[i].ptr = ptr;
	df_rc->ring[i].ttl = RAND_RANGE(DEFERRED_TTL_MIN, DEFERRED_TTL_MAX);
	if (df_rc_unlock() == 0) {
		df_rc->occupied_mask |= 1ULL << i;
		df_rc->ring_count++;
		df_rc_lock();
	}
	deferred_free_record_outstanding(df_rc->ring_count);

	df_ring_lock();

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
 * binding ownership gate is df_alloc_track_consume via
 * df_tracked_free_checked.  See Documentation/deferred-free.md "free_ring_entry corruption gating".
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

	df_tracked_free_checked(ptr, TRACKED_FREE_SITE_RING_DRAIN);
}

void deferred_free_tick(void)
{
	static unsigned int tick_count;
	unsigned int i;
	enum ring_unlock_result r;

	/* Cheap path: ring_count is read while still locked, but it lives
	 * in BSS (not in the protected ring), so this access is safe.
	 * ring_count is also zero when the ring has been disposed after
	 * an ENOMEM event, so this guard doubles as the ring==NULL bail.
	 * NOTE: even when ring_count == 0 we still fall through to the
	 * batch check below so the generation arena can age and retire --
	 * arena entries were admitted by prior evictions and their
	 * retirement clock must keep advancing regardless of current
	 * ring occupancy.
	 */

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

	/* Arena age-and-retire runs on every batched tick, even when the
	 * ring is empty or disposed.  Kept ahead of the ring drain so a
	 * retirement that free()s an alloc_track entry can, in the same
	 * tick, be re-populated by a fresh admission below. */
	df_gen_arena_tick();

	if (df_rc->ring_count == 0)
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
	r = df_ring_unlock();
	if (r == RING_UNLOCK_ENOMEM) {
		__atomic_add_fetch(&shm->stats.deferred_free.rw_restore_enomem,
				   1, __ATOMIC_RELAXED);
		df_ring_dispose_after_enomem();
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
	if (df_rc_unlock() != 0) {
		df_ring_lock();
		return;
	}

	for (i = 0; i < DEFERRED_RING_SIZE; i++) {
		void *ptr;

		if (df_rc->ring[i].ptr == NULL) {
			/*
			 * Stomped corpse: a fuzzed value-result syscall
			 * scribbled this slot's ptr to NULL while it was
			 * still marked occupied.  Reconcile the bookkeeping
			 * so occupied_mask and ring_count track reality;
			 * otherwise accumulated stomps drive occupied_mask
			 * toward ~0ULL and the enqueue path pins itself in
			 * the fallback immediate-free branch instead of
			 * using the ring.  occupied_mask now lives in the
			 * armored ring_control page (see struct comment),
			 * so this is the sole remaining path that lets its
			 * bits diverge from ring[]'s ptr state.
			 */
			if (df_rc->occupied_mask & (1ULL << i)) {
				df_rc->occupied_mask &= ~(1ULL << i);
				df_rc->ring_count--;
			}
			continue;
		}

		if (df_rc->ring[i].ttl > 0) {
			df_rc->ring[i].ttl--;
			continue;
		}

		/* TTL expired — free it.  Clear the slot BEFORE calling
		 * the free function so that if a signal interrupts us
		 * mid-free and we longjmp, the slot is already empty. */
		ptr = df_rc->ring[i].ptr;
		df_rc->ring[i].ptr = NULL;
		df_rc->occupied_mask &= ~(1ULL << i);
		df_rc->ring_count--;

		free_ring_entry(ptr, i);
	}

	df_rc_lock();

	df_ring_lock();
}

void deferred_free_flush(void)
{
	unsigned int i;
	enum ring_unlock_result r;

	/* Drain the generation arena unconditionally: the arena exists
	 * independently of the ring, and a child exiting with SEALED-but-
	 * not-yet-retired generations would otherwise leak the whole set
	 * (kernel reclaims the address space right after, but the retire
	 * discipline -- df_alloc_track_consume gate, corrupt-shape reject --
	 * is what we want to run against every held ptr, not the anonymous
	 * "process exit reclaims everything" path).  Runs BEFORE the ring
	 * drain, so a ptr that somehow lives in both is consumed and freed
	 * by the arena retire and the ring drain's consume then misses:
	 * one free either way. */
	df_gen_arena_flush();

	/* Ring already disposed by a prior ENOMEM event.  Nothing to
	 * flush; skip df_ring_unlock so we don't emit a "mprotect RW
	 * failed" log line on every child exit for the rest of the run. */
	if (df_rc->ring == NULL)
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
	r = df_ring_unlock();
	if (r == RING_UNLOCK_ENOMEM) {
		__atomic_add_fetch(&shm->stats.deferred_free.rw_restore_enomem,
				   1, __ATOMIC_RELAXED);
		df_ring_dispose_after_enomem();
		return;
	}
	if (r != RING_UNLOCK_OK)
		return;

	for (i = 0; i < DEFERRED_RING_SIZE; i++) {
		void *ptr;

		if (df_rc->ring[i].ptr == NULL)
			continue;

		/* Clear before invoking, mirroring tick: a signal that
		 * longjmps mid-free leaves the slot empty either way. */
		ptr = df_rc->ring[i].ptr;
		df_rc->ring[i].ptr = NULL;
		free_ring_entry(ptr, i);
	}
	if (df_rc_unlock() == 0) {
		df_rc->ring_count = 0;
		df_rc->occupied_mask = 0;
		df_rc_lock();
	}

	df_ring_lock();
}
