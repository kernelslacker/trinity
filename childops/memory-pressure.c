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
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/* Stay well under any realistic memory limit. */
#define PRESSURE_MIN_MB  4
#define PRESSURE_MAX_MB 32

bool memory_pressure(struct childdata *child)
{
	size_t len;
	void *region;
	volatile unsigned char *p;
	size_t stride, i;

	(void)child;

	/* Pick a random region size between PRESSURE_MIN_MB and PRESSURE_MAX_MB. */
	len = MB(PRESSURE_MIN_MB + (rand() % (PRESSURE_MAX_MB - PRESSURE_MIN_MB + 1)));

	region = mmap(NULL, len, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED)
		return true;

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

	munmap(region, len);

	__atomic_add_fetch(&shm->stats.memory_pressure_runs, 1, __ATOMIC_RELAXED);

	return true;
}
