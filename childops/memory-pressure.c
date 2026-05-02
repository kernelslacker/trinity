/*
 * memory_pressure - madvise(MADV_PAGEOUT) + refault to exercise OOM-adjacent
 * kernel paths.
 *
 * Evicting a large anonymous region forces the kernel to walk the LRU,
 * deactivate pages, and write them to the swap device (or zram/zswap).
 * Immediately reading the region back triggers page faults that must
 * allocate new physical pages, invoke the page fault handler, and re-read
 * from swap — exactly the allocation/rollback paths that are often reached
 * only under genuine memory pressure and that frequently contain incomplete
 * error handling or locking assumptions that differ from the steady-state
 * path.  Running other syscall fuzzing concurrently (in sibling children)
 * while these refaults are in flight further increases the chance of hitting
 * mid-allocation failure modes.
 */

#include <sys/mman.h>
#include <stdlib.h>

#include "arch.h"
#include "child.h"
#include "maps.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

bool memory_pressure(struct childdata *child)
{
	struct map *m;
	size_t len;
	void *region;
	volatile unsigned char *p;
	size_t stride, i;

	(void)child;

	/*
	 * Draw the region from the parent's inherited mapping pool instead
	 * of mmap()ing a fresh private allocation per invocation.  The pool
	 * is built once in the parent and shared COW into every child, so
	 * sibling memory_pressure invocations running concurrently will
	 * sometimes target the same physical pages — that convergence is
	 * the point: it amplifies LRU contention and exposes the
	 * eviction / refault race surface to multiple reclaimers at once,
	 * which is far harder to provoke with disjoint per-child regions.
	 *
	 * The pool is owned by the parent: do NOT munmap on cleanup.
	 * Tearing down a pool entry would unmap pages that every other
	 * sibling drawing the same map is still treating as live.
	 */
	m = get_map_with_prot(PROT_WRITE);
	if (m == NULL)
		return false;

	region = m->ptr;
	len = m->size;

	/*
	 * Dirty each page so MADV_PAGEOUT has real work to do.  Without
	 * this the pages are zero-filled and the kernel may skip the eviction
	 * (clean anonymous pages can simply be discarded rather than written
	 * to swap, which bypasses the reclaim writeback paths we want to hit).
	 */
	p = (volatile unsigned char *)region;
	for (i = 0; i < len; i += page_size)
		p[i] = (unsigned char)(i & 0xff);

	/* Evict: ask the kernel to reclaim the entire region. */
	madvise(region, len, MADV_PAGEOUT);

	/*
	 * Refault: read back one byte per page, forcing a page fault for each.
	 * Walk with a stride larger than page_size to avoid triggering
	 * readahead for contiguous pages, so each fault is handled
	 * independently by the allocator.
	 */
	stride = 3 * page_size;
	for (i = 0; i < len; i += stride)
		(void)p[i];

	__atomic_add_fetch(&shm->stats.memory_pressure_runs, 1, __ATOMIC_RELAXED);

	return true;
}
