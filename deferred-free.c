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

static struct deferred_entry ring[DEFERRED_RING_SIZE];
static unsigned int ring_count;

void deferred_free_init(void)
{
	memset(ring, 0, sizeof(ring));
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
