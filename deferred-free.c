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
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/mman.h>

#include "deferred-free.h"
#include "pc_format.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define DEFERRED_RING_SIZE	64
#define DEFERRED_TTL_MIN	5
#define DEFERRED_TTL_MAX	50

struct deferred_entry {
	void *ptr;
	void (*free_func)(void *);
	unsigned int ttl;
};

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
		outputerr("deferred_free: mprotect RW failed: %s\n",
			  strerror(errno));
		return false;
	}
	return true;
}

static void ring_lock(void)
{
	if (mprotect(ring, ring_bytes, PROT_NONE) != 0)
		outputerr("deferred_free: mprotect NONE failed: %s\n",
			  strerror(errno));
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
	ring_lock();
}

void deferred_free_enqueue(void *ptr, void (*free_func)(void *))
{
	unsigned int i;

	if (ptr == NULL)
		return;

	if (free_func == NULL)
		free_func = free;

	/*
	 * Reject pid-scribbled / canonical-out-of-range / misaligned values
	 * BEFORE they ever reach the ring.  Cluster-1/2/3 root cause
	 * (residual-cores triage 2026-05-02): a sibling fuzzed value-result
	 * syscall scribbles a tid/pid into rec->aN, the post handler does
	 * deferred_freeptr(&rec->aN) which arrives here, and N syscalls
	 * later deferred_free_tick() free()s the pid -- SIGSEGV with
	 * si_addr==si_pid.  Drop the bad value at the post-handler boundary
	 * (one counter bumped, ring slot stays empty) instead of letting
	 * the corruption propagate into the ring.  Gated on free_func==free
	 * because custom free funcs may legitimately receive non-heap
	 * tokens (caller knows what they're doing); same gating convention
	 * as the range_overlaps_shared check below.
	 */
	if (looks_like_corrupted_ptr(ptr) && free_func == free) {
		outputerr("deferred_free_enqueue: rejected suspicious ptr=%p "
			  "(pid-scribbled?)\n", ptr);
		shm->stats.post_handler_corrupt_ptr++;
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
	if (range_overlaps_shared((unsigned long)ptr, 1) && free_func == free) {
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
		free_func(ptr);
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
		if (ring[oldest].ptr != NULL && ring[oldest].free_func != NULL) {
			ring[oldest].free_func(ring[oldest].ptr);
			ring[oldest].ptr = NULL;
			ring_count--;
		}
	}

	/* Find an empty slot. */
	for (i = 0; i < DEFERRED_RING_SIZE; i++) {
		if (ring[i].ptr == NULL) {
			ring[i].ptr = ptr;
			ring[i].free_func = free_func;
			ring[i].ttl = RAND_RANGE(DEFERRED_TTL_MIN, DEFERRED_TTL_MAX);
			ring_count++;
			break;
		}
	}

	ring_lock();
}

void deferred_freeptr(unsigned long *p)
{
	void *ptr = (void *) *p;
	*p = 0;
	deferred_free_enqueue(ptr, NULL);
}

void deferred_free_tick(void)
{
	unsigned int i;

	/* Cheap path: ring_count is read while still locked, but it lives
	 * in BSS (not in the protected ring), so this access is safe. */
	if (ring_count == 0)
		return;

	/* On unlock failure the page is still PROT_NONE; bail rather
	 * than SEGV_ACCERR in the loop below.  Entries stay queued and
	 * will be retried on the next tick. */
	if (!ring_unlock())
		return;

	for (i = 0; i < DEFERRED_RING_SIZE; i++) {
		void *ptr;
		void (*fn)(void *);

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
		fn = ring[i].free_func;
		ring[i].ptr = NULL;
		ring_count--;

		/* Sanity-check ptr before invoking fn().  A sub-page address
		 * cannot be a real heap pointer; if we see one here it's
		 * almost certainly a fuzzed value-result syscall having
		 * scribbled a pid-shaped value into the ring before the
		 * mprotect guard was added (or a bypass that defeated it).
		 * Drop the pointer rather than crash on free(). */
		if ((unsigned long)ptr < 0x10000) {
			outputerr("deferred_free: rejected suspicious ptr=%p "
				  "in slot %u (looks pid-shaped)\n", ptr, i);
			shm->stats.deferred_free_corrupt_ptr++;
			continue;
		}

		fn(ptr);
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
		if (ring[i].ptr != NULL) {
			ring[i].free_func(ring[i].ptr);
			ring[i].ptr = NULL;
		}
	}
	ring_count = 0;

	ring_lock();
}
