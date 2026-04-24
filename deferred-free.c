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

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/mman.h>

#include "deferred-free.h"
#include "pc_format.h"
#include "random.h"
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

void deferred_free_init(void)
{
	const size_t bytes = sizeof(struct deferred_entry) * DEFERRED_RING_SIZE;

	ring = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANON, -1, 0);
	if (ring == MAP_FAILED) {
		outputerr("deferred_free_init: mmap %zu failed\n", bytes);
		exit(EXIT_FAILURE);
	}
	memset(ring, 0, bytes);
	track_shared_region((unsigned long)ring, bytes);
	ring_count = 0;
}

void deferred_free_enqueue(void *ptr, void (*free_func)(void *))
{
	unsigned int i;

	if (ptr == NULL)
		return;

	if (free_func == NULL)
		free_func = free;

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
			return;
		}
	}
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

	if (ring_count == 0)
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
		fn(ptr);
	}
}

void deferred_free_flush(void)
{
	unsigned int i;

	for (i = 0; i < DEFERRED_RING_SIZE; i++) {
		if (ring[i].ptr != NULL) {
			ring[i].free_func(ring[i].ptr);
			ring[i].ptr = NULL;
		}
	}
	ring_count = 0;
}
